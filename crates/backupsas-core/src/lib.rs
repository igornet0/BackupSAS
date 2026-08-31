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
    BackupSasConfig, RepositoryConfig, ServerConfig, DEFAULT_CHUNK_SIZE, DEFAULT_LISTEN,
    DEFAULT_REPO_NAME,
};
pub use enrollment::{EnrollmentRecord, EnrollmentSecret};
pub use envelope::{AuthProof, Challenge};
pub use error::{BackupSasError, Result};
pub use format::{
    ChunkInfo, CommitRecord, EncryptionInfo, EncryptionScheme, DEFAULT_KEY_ID, FORMAT_VERSION,
};
pub use hash::{hash_bytes, parse_hash_bytes, verify_hash, HASH_PREFIX};
pub use id::{
    BackupId, ClientId, DatabaseId, ParticipantId, RepositoryId, ServerId, SessionId,
};
pub use identity::Identity;
pub use keys::{BackupEncryptionKey, Fingerprint, PublicKey, SecretKey};
pub use manifest::BackupManifest;
pub use session::{SessionInfo, SessionKeys, SessionState};
pub use state::BackupState;
pub use trust::{pin_matches, TrustedPeer};
pub use verify::{verify_backup_dir, VerifyFailure, VerifyResult};
