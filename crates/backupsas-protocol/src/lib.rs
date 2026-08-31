//! BackupSAS Protocol: framed binary messages over a TLS stream.

pub mod v1;

mod codec;
mod frame;
mod message;
mod wire;

pub use codec::{read_frame, write_frame};
pub use frame::{FrameHeader, MAGIC, MAX_FRAME_SIZE, PROTOCOL_VERSION, PROTOCOL_VERSION_V1};
pub use message::{
    ChunkMismatch, Features, Message, FEATURE_ENROLL, FEATURE_RESUME, FEATURE_SESSION,
    FEATURE_VERIFY, FEATURES_V1, FEATURES_V2,
};
