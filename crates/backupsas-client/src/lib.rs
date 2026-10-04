//! BackupSAS client SDK: identity auth, enrollment, chunking, and upload.

mod authentication;
mod backup;
mod chunker;
mod connection;
mod encryptor;
mod ops;
mod restore;
mod source;
mod target;
mod tls;

pub mod client;

pub use authentication::AuthenticatedSession;
pub use backup::{UploadHandle, UploadOutcome};
pub use chunker::{Chunk, ChunkIter, chunk_reader};
pub use client::BackupSasClient;
pub use encryptor::{Aes256GcmEncryptor, ChunkEncryptor, EncryptedChunk};
pub use ops::TransferOffer;
pub use restore::BackupHandle;
pub use source::{BackupSource, BackupSourceMetadata, MemoryBackupSource};
pub use target::{FileRestoreTarget, MemoryRestoreTarget, RestoreMetadata, RestoreTarget};
pub use tls::{client_tls_from_pem, load_client_tls};
