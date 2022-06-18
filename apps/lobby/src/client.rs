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

use crate::packets::{
    ClientLobbyIpcType, PacketHeader, PacketRaw, PacketSegmentHeader, SegmentType,
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

            println!("{:02X?}", data);

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
                    ClientLobbyIpcType::ClientVersionInfo => {
                        todo!()
                    }
                    _ => println!("Unknown IPC type {}", ipc_type_num),
                }
            }
            _ => (),
        }

        Ok(())
    }

    async fn send_packet(
        &mut self,
        segment_header: PacketSegmentHeader,
        mut data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut send_cursor = Cursor::new(vec![]);

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
            .expect("Could not write packet header");

        segment_header
            .write_to(&mut send_cursor)
            .expect("Could not write packet segment header");

        send_cursor
            .write_buf(&mut data)
            .await
            .expect("Could not write packet data");

        let sending = send_cursor.get_ref();
        println!("sending packet: {:02X?}", sending);
        self.stream
            .write_all(sending)
            .await
            .expect("Could not write packet");

        Ok(())
    }
}
