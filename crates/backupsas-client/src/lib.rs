//! BackupSAS client SDK: identity auth, enrollment, chunking, and upload.

mod authentication;
mod backup;
mod chunker;
mod connection;
mod encryptor;
mod source;
mod tls;

pub mod client;

pub use authentication::AuthenticatedSession;
pub use backup::{BackupHandle, UploadOutcome};
pub use chunker::{chunk_reader, Chunk, ChunkIter};
pub use client::BackupSasClient;
pub use encryptor::{Aes256GcmEncryptor, ChunkEncryptor, EncryptedChunk};
pub use source::{BackupSource, BackupSourceMetadata, MemoryBackupSource};
pub use tls::load_client_tls;
