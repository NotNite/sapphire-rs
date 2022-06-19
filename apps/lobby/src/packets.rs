use binrw::{BinRead, BinWrite};
use num_enum::TryFromPrimitive;
use std::mem::size_of;

#[derive(BinRead, Debug)]
#[br(repr = u16)]
pub enum CompressionType {
    None = 0,
    Zlib = 1,
    Oodle = 2,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct PacketHeader {
    pub unknown_0: u64,
    pub unknown_8: u64,

    pub timestamp: u64,
    pub size: u32,
    pub connection_type: u16,
    pub count: u16,

    pub unknown_20: u8,
    pub is_compressed: u8,
    pub unknown_24: u16,
    pub uncompressed_size: u32,
}

#[derive(BinRead, PartialEq, Eq, Debug, TryFromPrimitive)]
#[br(repr = u16)]
#[repr(u16)]
pub enum SegmentType {
    SessionInit = 1,
    Ipc = 3,
    KeepAlive = 7,
    EncryptionInit = 9,
}

#[derive(BinRead, BinWrite, Debug)]
pub struct PacketSegmentHeader {
    pub size: u32,
    pub source_actor: u32,
    pub target_actor: u32,
    pub segment_type: u16,
    pub padding: u16,
}

impl PacketSegmentHeader {
    pub fn new(
        segment_type: u16,
        size: u32,
        source_actor: u32,
        target_actor: u32,
    ) -> PacketSegmentHeader {
        PacketSegmentHeader {
            size: (size_of::<PacketSegmentHeader>() as u32) + size,
            source_actor,
            target_actor,
            segment_type,
            padding: 0,
        }
    }
}

pub struct PacketRaw {
    pub segment_header: PacketSegmentHeader,
    pub data: Vec<u8>,
}
