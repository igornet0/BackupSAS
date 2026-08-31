use crate::canonical::canonical_bytes;
use crate::error::{BackupSasError, Result};
use crate::format::{ChunkInfo, DEFAULT_KEY_ID, EncryptionInfo, EncryptionScheme, FORMAT_VERSION};
use crate::hash::hash_bytes;
use crate::id::{BackupId, DatabaseId};
use crate::merkle::{merkle_root, verify_merkle_root};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub backup_id: BackupId,
    pub database_id: DatabaseId,
    pub chunk_size: u64,
    pub total_size: u64,
    pub encryption: EncryptionInfo,
    pub chunks: Vec<ChunkInfo>,
    pub root_hash: String,
    pub manifest_hash: String,
}

/// Manifest body used for canonical hashing (excludes `manifest_hash`).
#[derive(Serialize)]
struct ManifestForHash<'a> {
    format_version: u32,
    backup_id: &'a BackupId,
    database_id: &'a DatabaseId,
    chunk_size: u64,
    total_size: u64,
    encryption: &'a EncryptionInfo,
    chunks: &'a [ChunkInfo],
    root_hash: &'a str,
}

impl BackupManifest {
    pub fn chunk_count(&self) -> u32 {
        self.chunks.len() as u32
    }

    pub fn chunk_hashes(&self) -> Vec<String> {
        self.chunks.iter().map(|c| c.hash.clone()).collect()
    }

    pub fn new(
        backup_id: BackupId,
        database_id: DatabaseId,
        chunk_size: u64,
        total_size: u64,
        chunks: Vec<ChunkInfo>,
        key_id: impl Into<String>,
    ) -> Self {
        let mut manifest = Self {
            format_version: FORMAT_VERSION,
            backup_id,
            database_id,
            chunk_size,
            total_size,
            encryption: EncryptionInfo {
                scheme: EncryptionScheme::Aes256Gcm,
                key_id: key_id.into(),
            },
            chunks,
            root_hash: String::new(),
            manifest_hash: String::new(),
        };
        manifest.seal();
        manifest
    }

    pub fn from_chunk_hashes(
        backup_id: BackupId,
        database_id: DatabaseId,
        chunk_size: u64,
        total_size: u64,
        chunk_hashes: Vec<String>,
        ciphertext_sizes: Vec<u64>,
        key_id: impl Into<String>,
    ) -> Result<Self> {
        if chunk_hashes.len() != ciphertext_sizes.len() {
            return Err(BackupSasError::InvalidManifest(
                "chunk_hashes and ciphertext_sizes length mismatch".into(),
            ));
        }
        let chunks = chunk_hashes
            .into_iter()
            .zip(ciphertext_sizes)
            .enumerate()
            .map(|(seq, (hash, size))| ChunkInfo {
                sequence: seq as u32,
                size,
                hash,
            })
            .collect();
        Ok(Self::new(
            backup_id,
            database_id,
            chunk_size,
            total_size,
            chunks,
            key_id,
        ))
    }

    pub fn seal(&mut self) {
        self.root_hash = merkle_root(&self.chunk_hashes()).unwrap_or_default();
        self.manifest_hash.clear();
        self.manifest_hash = self.compute_manifest_hash();
    }

    pub fn compute_manifest_hash(&self) -> String {
        let value = serde_json::to_value(ManifestForHash {
            format_version: self.format_version,
            backup_id: &self.backup_id,
            database_id: &self.database_id,
            chunk_size: self.chunk_size,
            total_size: self.total_size,
            encryption: &self.encryption,
            chunks: &self.chunks,
            root_hash: &self.root_hash,
        })
        .expect("manifest for hash serialization");
        let bytes = canonical_bytes(&value).expect("canonical manifest");
        hash_bytes(&bytes)
    }

    pub fn verify_manifest_hash(&self) -> Result<()> {
        let expected = self.compute_manifest_hash();
        if self.manifest_hash != expected {
            return Err(BackupSasError::InvalidManifest(format!(
                "manifest_hash mismatch: expected {expected}, got {}",
                self.manifest_hash
            )));
        }
        Ok(())
    }

    pub fn verify_root_hash(&self) -> Result<()> {
        verify_merkle_root(&self.chunk_hashes(), &self.root_hash)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(BackupSasError::InvalidManifest(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        if self.encryption.scheme != EncryptionScheme::Aes256Gcm {
            return Err(BackupSasError::InvalidManifest(
                "unsupported encryption scheme".into(),
            ));
        }
        for (i, chunk) in self.chunks.iter().enumerate() {
            if chunk.sequence != i as u32 {
                return Err(BackupSasError::InvalidManifest(format!(
                    "chunks not contiguous at index {i}: sequence {}",
                    chunk.sequence
                )));
            }
            if !chunk.hash.starts_with(crate::hash::HASH_PREFIX) {
                return Err(BackupSasError::InvalidManifest(format!(
                    "chunk {i} hash missing blake3 prefix"
                )));
            }
        }
        self.verify_root_hash()?;
        self.verify_manifest_hash()?;
        Ok(())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

impl Default for EncryptionInfo {
    fn default() -> Self {
        Self {
            scheme: EncryptionScheme::Aes256Gcm,
            key_id: DEFAULT_KEY_ID.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chunks() -> Vec<ChunkInfo> {
        vec![
            ChunkInfo {
                sequence: 0,
                size: 32,
                hash: hash_bytes(b"chunk0"),
            },
            ChunkInfo {
                sequence: 1,
                size: 32,
                hash: hash_bytes(b"chunk1"),
            },
        ]
    }

    #[test]
    fn seal_and_verify() {
        let manifest = BackupManifest::new(
            BackupId::new(),
            DatabaseId::new(),
            64,
            128,
            sample_chunks(),
            DEFAULT_KEY_ID,
        );
        assert!(manifest.manifest_hash.starts_with("blake3:"));
        assert!(manifest.root_hash.starts_with("blake3:"));
        manifest.validate().unwrap();
    }

    #[test]
    fn tampered_manifest_hash_fails() {
        let mut manifest = BackupManifest::new(
            BackupId::new(),
            DatabaseId::new(),
            8,
            8,
            vec![ChunkInfo {
                sequence: 0,
                size: 8,
                hash: hash_bytes(b"x"),
            }],
            DEFAULT_KEY_ID,
        );
        manifest.manifest_hash = "blake3:deadbeef".into();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn tampered_root_hash_fails() {
        let mut manifest = BackupManifest::new(
            BackupId::new(),
            DatabaseId::new(),
            8,
            8,
            vec![ChunkInfo {
                sequence: 0,
                size: 8,
                hash: hash_bytes(b"x"),
            }],
            DEFAULT_KEY_ID,
        );
        manifest.root_hash = "blake3:deadbeef".into();
        assert!(manifest.validate().is_err());
    }
}
