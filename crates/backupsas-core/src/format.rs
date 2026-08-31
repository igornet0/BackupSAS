use crate::error::{BackupSasError, Result};
use crate::id::BackupId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_KEY_ID: &str = "local:default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkInfo {
    pub sequence: u32,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionInfo {
    pub scheme: EncryptionScheme,
    pub key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionScheme {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl EncryptionScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

/// Sole proof of backup finalization. Integrity by equality with manifest fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRecord {
    pub format_version: u32,
    pub backup_id: BackupId,
    pub root_hash: String,
    pub manifest_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub committed_at: OffsetDateTime,
}

impl CommitRecord {
    pub fn new(
        backup_id: BackupId,
        root_hash: String,
        manifest_hash: String,
        committed_at: OffsetDateTime,
    ) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            backup_id,
            root_hash,
            manifest_hash,
            committed_at,
        }
    }

    pub fn validate_version(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(BackupSasError::InvalidManifest(format!(
                "unsupported commit format_version {}",
                self.format_version
            )));
        }
        Ok(())
    }

    pub fn to_vec_pretty(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let record: Self = serde_json::from_slice(bytes)?;
        record.validate_version()?;
        Ok(record)
    }
}
