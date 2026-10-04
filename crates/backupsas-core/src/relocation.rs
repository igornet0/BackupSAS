//! Node-to-node transfer types and signed relocation notices.
//!
//! When node A moves or copies backups to node B, A records a
//! [`RelocationNotice`] signed by its identity. The owning database fetches
//! the notice from A (whose key it already pins), verifies it, learns B's
//! [`ConnectDescriptor`], and updates where the backups live.

use crate::canonical::canonical_bytes;
use crate::descriptor::ConnectDescriptor;
use crate::error::{BackupSasError, Result};
use crate::id::{BackupId, ClientId, ServerId};
use crate::identity::Identity;
use crate::keys::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

const NOTICE_DOMAIN: &[u8] = b"backupsas-relocation-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferMode {
    /// Data moves to the target; the source deletes it after the owner acks.
    Move,
    /// Data is replicated; the source keeps its copy.
    Copy,
}

impl TransferMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Move => "move",
            Self::Copy => "copy",
        }
    }
}

impl fmt::Display for TransferMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TransferMode {
    type Err = BackupSasError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "move" => Ok(Self::Move),
            "copy" => Ok(Self::Copy),
            other => Err(BackupSasError::Protocol(format!(
                "unknown transfer mode `{other}`"
            ))),
        }
    }
}

/// Summary of a stored backup as reported to an authorized client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteBackupInfo {
    pub backup_id: String,
    pub database_id: String,
    pub repository: String,
    pub state: String,
    pub total_size: u64,
    pub chunk_count: u32,
    /// RFC 3339, empty while uploading.
    #[serde(default)]
    pub committed_at: String,
    /// `true` once a `move` relocated this backup away (kept until acked).
    #[serde(default)]
    pub relocated: bool,
    /// Manifest hash of a complete backup (empty while uploading). Equal
    /// hashes on two nodes mean the copies are byte-identical.
    #[serde(default)]
    pub manifest_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationNotice {
    pub relocation_id: String,
    pub mode: TransferMode,
    /// Node that held the data and signed this notice.
    pub source_server_id: ServerId,
    /// Database identity that owns the backups.
    pub owner_client_id: ClientId,
    pub repository: String,
    pub backup_ids: Vec<BackupId>,
    /// Where the data now lives.
    pub target: ConnectDescriptor,
    /// Repository name on the target node.
    pub target_repository: String,
    /// Unix seconds.
    pub created_at: u64,
    #[serde(default)]
    pub signature: String,
}

impl RelocationNotice {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        if let Some(map) = value.as_object_mut() {
            map.remove("signature");
        }
        let mut out = NOTICE_DOMAIN.to_vec();
        out.extend_from_slice(&canonical_bytes(&value)?);
        Ok(out)
    }

    pub fn sign(mut self, source: &Identity) -> Result<Self> {
        self.signature.clear();
        self.signature = hex::encode(source.sign(&self.signing_bytes()?));
        Ok(self)
    }

    /// Verify with the source node's pinned key, and check the embedded
    /// target descriptor is itself validly self-signed.
    pub fn verify(&self, source_key: &PublicKey) -> Result<()> {
        let sig = hex::decode(&self.signature)
            .map_err(|e| BackupSasError::Auth(format!("notice signature hex: {e}")))?;
        crate::crypto::verify(source_key, &self.signing_bytes()?, &sig)?;
        self.target.verify()?;
        if self.target.server_id == self.source_server_id {
            return Err(BackupSasError::Protocol(
                "relocation target equals source".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ParticipantId;

    fn server() -> (Identity, ServerId) {
        let id = Identity::generate_server();
        let ParticipantId::Server(sid) = id.id else {
            unreachable!()
        };
        (id, sid)
    }

    fn notice() -> (RelocationNotice, Identity) {
        let (a, a_id) = server();
        let (b, b_id) = server();
        let target = ConnectDescriptor::new(
            b_id,
            b.public_key,
            vec!["b:7420".into()],
            "localhost",
            "pem",
            vec!["avrora-prod".into()],
            vec![],
        )
        .sign(&b)
        .unwrap();
        let n = RelocationNotice {
            relocation_id: "rel_1".into(),
            mode: TransferMode::Move,
            source_server_id: a_id,
            owner_client_id: ClientId::new(),
            repository: "avrora-prod".into(),
            backup_ids: vec![BackupId::new()],
            target,
            target_repository: "avrora-prod".into(),
            created_at: 1,
            signature: String::new(),
        }
        .sign(&a)
        .unwrap();
        (n, a)
    }

    #[test]
    fn notice_roundtrip() {
        let (n, a) = notice();
        let json = serde_json::to_string(&n).unwrap();
        let back: RelocationNotice = serde_json::from_str(&json).unwrap();
        back.verify(&a.public_key).unwrap();
    }

    #[test]
    fn notice_rejects_other_signer_and_tamper() {
        let (mut n, a) = notice();
        let (other, _) = server();
        assert!(n.verify(&other.public_key).is_err());
        n.mode = TransferMode::Copy;
        assert!(n.verify(&a.public_key).is_err());
    }

    #[test]
    fn mode_parse() {
        assert_eq!("move".parse::<TransferMode>().unwrap(), TransferMode::Move);
        assert!("x".parse::<TransferMode>().is_err());
    }
}
