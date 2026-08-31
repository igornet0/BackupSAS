use crate::state::BackupState;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BackupSasError {
    #[error("invalid id `{0}`")]
    InvalidId(String),

    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    #[error("backup `{0}` not found")]
    BackupNotFound(String),

    #[error("repository `{0}` not found")]
    RepositoryNotFound(String),

    #[error("backup `{id}` is in state {actual:?}, expected {expected:?}")]
    InvalidState {
        id: String,
        actual: BackupState,
        expected: BackupState,
    },

    #[error("backup `{0}` is already complete and immutable")]
    AlreadyComplete(String),

    #[error("chunk sequence mismatch: expected {expected}, got {got}")]
    ChunkSequence { expected: u32, got: u32 },

    #[error("chunk {seq} hash mismatch: expected {expected}, got {actual}")]
    ChunkHashMismatch {
        seq: u32,
        expected: String,
        actual: String,
    },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("enrollment failed: {0}")]
    Enrollment(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("trust pin mismatch: expected {expected}, got {actual}")]
    TrustPinMismatch { expected: String, actual: String },

    #[error("tls error: {0}")]
    Tls(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(String),

    #[error("path error at {}: {message}", path.display())]
    Path { path: PathBuf, message: String },

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for BackupSasError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, BackupSasError>;
