//! Shared types for BackupSAS: identity, crypto, manifests, and errors.

pub mod canonical;
pub mod config;
pub mod crypto;
pub mod enrollment;
pub mod envelope;
pub mod error;
pub mod format;
pub mod hash;
pub mod id;
pub mod identity;
pub mod keys;
pub mod manifest;
pub mod merkle;
pub mod session;
pub mod state;
pub mod trust;
pub mod verify;

pub use config::{
    BackupSasConfig, DEFAULT_CHUNK_SIZE, DEFAULT_LISTEN, DEFAULT_REPO_NAME, RepositoryConfig,
    ServerConfig,
};
pub use enrollment::{EnrollmentRecord, EnrollmentSecret};
pub use envelope::{AuthProof, Challenge};
pub use error::{BackupSasError, Result};
pub use format::{
    ChunkInfo, CommitRecord, DEFAULT_KEY_ID, EncryptionInfo, EncryptionScheme, FORMAT_VERSION,
};
pub use hash::{HASH_PREFIX, hash_bytes, parse_hash_bytes, verify_hash};
pub use id::{BackupId, ClientId, DatabaseId, ParticipantId, RepositoryId, ServerId, SessionId};
pub use identity::Identity;
pub use keys::{BackupEncryptionKey, Fingerprint, PublicKey, SecretKey};
pub use manifest::BackupManifest;
pub use session::{SessionInfo, SessionKeys, SessionState};
pub use state::BackupState;
pub use trust::{TrustedPeer, pin_matches};
pub use verify::{VerifyFailure, VerifyResult, verify_backup_dir};
