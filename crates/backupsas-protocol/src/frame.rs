use backupsas_core::{BackupSasError, Result};

pub const MAGIC: &[u8; 4] = b"BSAS";
pub const PROTOCOL_VERSION: u8 = 2;
pub const PROTOCOL_VERSION_V1: u8 = 1;
/// 64 MiB chunk + 1 MiB of headers / hash / id overhead.
pub const MAX_FRAME_SIZE: u32 = 65 * 1024 * 1024;
pub const HEADER_LEN: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub msg_type: u8,
    pub payload_len: u32,
}

impl FrameHeader {
    pub fn new(msg_type: u8, payload_len: u32) -> Result<Self> {
        if payload_len > MAX_FRAME_SIZE {
            return Err(BackupSasError::Protocol(format!(
                "frame payload {payload_len} exceeds max {MAX_FRAME_SIZE}"
            )));
        }
        Self::with_version(PROTOCOL_VERSION, msg_type, payload_len)
    }

    pub fn with_version(version: u8, msg_type: u8, payload_len: u32) -> Result<Self> {
        if payload_len > MAX_FRAME_SIZE {
            return Err(BackupSasError::Protocol(format!(
                "frame payload {payload_len} exceeds max {MAX_FRAME_SIZE}"
            )));
        }
        if version != PROTOCOL_VERSION && version != PROTOCOL_VERSION_V1 {
            return Err(BackupSasError::Protocol(format!(
                "unsupported protocol version {version}"
            )));
        }
        Ok(Self {
            version,
            msg_type,
            payload_len,
        })
    }

    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(MAGIC);
        buf[4] = self.version;
        buf[5] = self.msg_type;
        buf[6..10].copy_from_slice(&self.payload_len.to_le_bytes());
        buf
    }

    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self> {
        if &buf[0..4] != MAGIC {
            return Err(BackupSasError::Protocol("invalid magic".into()));
        }
        let payload_len = u32::from_le_bytes(buf[6..10].try_into().unwrap());
        Self::with_version(buf[4], buf[5], payload_len)
    }
}
