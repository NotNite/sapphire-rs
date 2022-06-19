use std::{
    error::Error,
    io::Cursor,
    mem::size_of,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    ipc::{ClientLobbyIpcType, IPCHeader, IPCServiceAccount, IPCServiceIDInfo},
    packets::{PacketHeader, PacketRaw, PacketSegmentHeader, SegmentType},
};
use binrw::{BinRead, BinWrite};
use brokefish::Brokefish;

pub struct Client {
    pub stream: TcpStream,
    pub encryption_key: Option<Vec<u8>>,
}

impl Client {
    pub async fn handle(&mut self) {
        let mut buf: Vec<u8> = vec![0; 2048];

        loop {
            let n = self
                .stream
                .read(&mut buf)
                .await
                .expect("failed to read data from socket");

            if n == 0 {
                return;
            }

            self.handle_packets(&buf[0..n])
                .await
                .expect("could not handle packet");
        }
    }

    async fn handle_packets(&mut self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        println!("recv packet: {:02X?}", buf);
        let mut cursor = Cursor::new(buf);

        let header = PacketHeader::read(&mut cursor).expect("could not parse packet header");
        println!("{:#?}", header);

        for _ in 0..header.count {
            let segment_header = PacketSegmentHeader::read(&mut cursor)
                .expect("could not parse packet segment header");
            println!("{:#?}", segment_header);

            let data_size =
                (segment_header.size - (size_of::<PacketSegmentHeader>() as u32)) as usize;
            let mut data: Vec<u8> = vec![0; data_size];
            cursor
                .read_exact(&mut data)
                .await
                .expect("could not read data");

            println!("packet data: {:02X?}", data);

            let packet = PacketRaw {
                segment_header,
                data,
            };

            self.handle_packet(packet).await?;
        }
        Ok(())
    }

    async fn handle_packet(&mut self, packet: PacketRaw) -> Result<(), Box<dyn Error>> {
        // todo: store this enum in the struct
        let segment_type: SegmentType = SegmentType::try_from(packet.segment_header.segment_type)
            .expect("couldn't determine segment type");

        match segment_type {
            SegmentType::KeepAlive => {
                let id = &packet.data[0..4];
                let timestamp = &packet.data[4..8];
                let segment_header = PacketSegmentHeader::new(0x08, 0x08, 0, 0);

                let mut data: [u8; 8] = [0; 8];
                data[0..4].copy_from_slice(id);
                data[4..8].copy_from_slice(timestamp);

                self.send_packet(segment_header, &data)
                    .await
                    .expect("failed to response to keepalive");
            }
            SegmentType::EncryptionInit => {
                let key = &packet.data[100..104];
                let key_phrase = &packet.data[36..68];

                let mut base_key: [u8; 0x2c] = [0; 0x2c];
                base_key[0] = 0x78;
                base_key[1] = 0x56;
                base_key[2] = 0x34;
                base_key[3] = 0x12;
                base_key[4..8].copy_from_slice(key);

                // the game ver (0xD417 = 6100)
                base_key[8] = 0xd4;
                base_key[9] = 0x17;
                base_key[12..44].copy_from_slice(key_phrase);

                let digest = md5::compute(base_key).to_vec();
                self.encryption_key = Some(digest);

                let mut send_data: [u8; 0x290] = [0; 0x290];
                send_data[0..4].copy_from_slice(&(0xe0003c2a_u32).to_le_bytes());

                self.send_packet(PacketSegmentHeader::new(0x0a, 0x290, 0, 0), &send_data)
                    .await?;
            }
            SegmentType::Ipc => {
                let data = {
                    if let Some(enc_key) = &self.encryption_key {
                        let enc_data = &packet.data[0..packet.data.len() - 0x08];
                        let bf = Brokefish::new(enc_key);
                        let decrypted = bf.decrypt(enc_data);
                        println!("decrypted: {:02X?}", decrypted);

                        let mut data: Vec<u8> = vec![0; packet.data.len()];
                        data[0..packet.data.len() - 0x08].copy_from_slice(&decrypted);

                        data
                    } else {
                        packet.data
                    }
                };

                let ipc_type_num =
                    u16::from_le_bytes(data[2..4].try_into().expect("couldn't determine IPC type"));
                let ipc_type = ClientLobbyIpcType::try_from(ipc_type_num)
                    .expect("couldn't determine IPC type");

                match ipc_type {
                    ClientLobbyIpcType::ClientVersionInfo => self.send_service_account().await?,
                    _ => println!("Unknown IPC type {}", ipc_type_num),
                }
            }
            _ => (),
        }

        Ok(())
    }

    async fn send_service_account(&mut self) -> Result<(), Box<dyn Error>> {
        let mut service_id_info = IPCServiceIDInfo::default();
        let mut name_buf: [u8; 0x44] = [0; 0x44];
        let name = "FINAL FANTASY XIV".as_bytes();
        name_buf[0..name.len()].copy_from_slice(name);

        let service_account = IPCServiceAccount {
            id: 0,
            unknown: 0,
            index: 0,
            name: name_buf,
        };

        service_id_info.add_service_account(service_account);

        let mut writer = Cursor::new(Vec::new());
        service_id_info
            .write_to(&mut writer)
            .expect("failed to write service ID info");

        println!("sending service account");
        self.send_ipc_packet(12, writer.get_ref()).await?;

        Ok(())
    }

    async fn send_ipc_packet(
        &mut self,
        ipc_type: u16,
        mut data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let ipc_header = IPCHeader::new(0, ipc_type);
        let size = (size_of::<IPCHeader>() as u32) + (data.len() as u32);

        let segment_header = PacketSegmentHeader::new(3, size, 0xe001c898, 0xe001c898);
        let mut buf: Cursor<Vec<u8>> = Cursor::new(vec![0; size as usize]);

        ipc_header
            .write_to(&mut buf)
            .expect("could not write IPC header");

        buf.write_buf(&mut data)
            .await
            .expect("could not write IPC data");

        self.send_packet(segment_header, buf.get_ref()).await?;

        Ok(())
    }

    async fn send_packet(
        &mut self,
        segment_header: PacketSegmentHeader,
        mut data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut send_cursor = Cursor::new(Vec::new());

        let size = size_of::<PacketHeader>() + size_of::<PacketSegmentHeader>() + data.len();
        let packet_header = PacketHeader {
            unknown_0: 0,
            unknown_8: 0,

            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            size: size as u32,
            connection_type: 0,
            count: 1,

            unknown_20: 1,
            is_compressed: 0,
            unknown_24: 0,
            uncompressed_size: 0,
        };

        packet_header
            .write_to(&mut send_cursor)
            .expect("could not write packet header");
        segment_header
            .write_to(&mut send_cursor)
            .expect("could not write packet segment header");

        let mut packet_data_cursor = Cursor::new(Vec::new());
        packet_data_cursor
            .write_buf(&mut data)
            .await
            .expect("could not write packet data");

        let segment_type = SegmentType::try_from(segment_header.segment_type).ok();

        // TODO
        let unencrypted_data = packet_data_cursor.get_ref();
        if segment_type == Some(SegmentType::Ipc) && self.encryption_key.is_some() {
            let enc_key = self.encryption_key.as_ref().unwrap();
            println!("encrypting");

            let bf = Brokefish::new(enc_key);
            let data_to_encrypt = &unencrypted_data[0..unencrypted_data.len() - 0x10];
            let mut enc_data: Vec<u8> = vec![0; unencrypted_data.len()];

            let enc_result = &bf.encrypt(data_to_encrypt);
            enc_data[0..enc_result.len()].copy_from_slice(enc_result);

            send_cursor
                .write_buf(&mut &enc_data[..])
                .await
                .expect("could not write encrypted packet data");
        } else {
            send_cursor
                .write_buf(&mut &unencrypted_data[..])
                .await
                .expect("could not write packet data");
        }

        let sending = send_cursor.get_ref();
        println!("sending packet: {:02X?}", sending);
        self.stream
            .write_all(sending)
            .await
            .expect("could not write packet");

        Ok(())
    }
}
