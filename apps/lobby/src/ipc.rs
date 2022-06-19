use binrw::BinWrite;
use num_enum::TryFromPrimitive;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(BinWrite)]
pub struct IPCHeader {
    reserved: u16,
    ipc_type: u16,
    padding: u16,
    server_id: u16,
    timestamp: u32,
    padding1: u32,
}

// todo: make this a trait or whatever rust shit can save me from this fresh hell
impl IPCHeader {
    pub fn new(server_id: u16, ipc_type: u16) -> IPCHeader {
        IPCHeader {
            reserved: 0,
            ipc_type,
            padding: 0,
            server_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs() as u32,
            padding1: 0,
        }
    }
}

#[derive(TryFromPrimitive)]
#[repr(u16)]
pub enum ClientLobbyIpcType {
    ReqCharList = 0x0003,
    ReqEnterWorld = 0x0004,
    ClientVersionInfo = 0x0005,

    ReqCharDelete = 0x000a,
    ReqCharCreate = 0x000b,
}

#[derive(BinWrite, Copy, Clone)]
pub struct IPCServiceAccount {
    pub id: u32,
    pub unknown: u32,
    pub index: u32,
    pub name: [u8; 0x44],
}

impl Default for IPCServiceAccount {
    fn default() -> Self {
        IPCServiceAccount {
            id: 0,
            unknown: 0,
            index: 0,
            name: [0; 0x44],
        }
    }
}

#[derive(BinWrite)]
pub struct IPCServiceIDInfo {
    seq: u64,
    padding: u8,
    service_accounts_len: u8,
    u1: u8,
    u2: u8,
    padding1: u8,
    service_accounts: [IPCServiceAccount; 8],
}

impl Default for IPCServiceIDInfo {
    fn default() -> IPCServiceIDInfo {
        IPCServiceIDInfo {
            seq: 1,
            padding: 0,
            service_accounts_len: 0,
            u1: 3,
            u2: 0x99,
            padding1: 0,
            service_accounts: [IPCServiceAccount::default(); 8],
        }
    }
}

impl IPCServiceIDInfo {
    pub fn add_service_account(&mut self, mut acc: IPCServiceAccount) {
        let idx = self.service_accounts_len;

        acc.index = idx as u32;
        self.service_accounts_len += 1;
        self.service_accounts[idx as usize] = acc;
    }
}
