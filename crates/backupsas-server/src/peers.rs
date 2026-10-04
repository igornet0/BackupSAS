//! Outgoing node-to-node links (this node acting as a client of another node).
//!
//! The node uses a dedicated client identity (`identity/node-client/`) to
//! enroll on peers. Each peer is pinned by its connect descriptor.

use backupsas_client::BackupSasClient;
use backupsas_core::{
    BackupEncryptionKey, BackupSasConfig, BackupSasError, ConnectDescriptor, EnrollmentSecret,
    Identity, Result,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub name: String,
    pub descriptor: ConnectDescriptor,
    /// Repository on the peer that receives transfers.
    pub repository: String,
    pub added_at: u64,
}

pub struct PeerStore {
    dir: PathBuf,
}

impl PeerStore {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("peers");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(BackupSasError::InvalidId(format!("peer name `{name}`")));
        }
        Ok(self.dir.join(format!("{name}.json")))
    }

    pub fn get(&self, name: &str) -> Result<PeerRecord> {
        let path = self.path(name)?;
        let bytes =
            fs::read(&path).map_err(|_| BackupSasError::Other(format!("unknown peer `{name}`")))?;
        let record: PeerRecord = serde_json::from_slice(&bytes)?;
        record.descriptor.verify()?;
        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<PeerRecord>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                out.push(serde_json::from_slice(&fs::read(&path)?)?);
            }
        }
        Ok(out)
    }

    pub fn save(&self, record: &PeerRecord) -> Result<()> {
        backupsas_storage::paths::atomic_write(
            &self.path(&record.name)?,
            &serde_json::to_vec_pretty(record)?,
        )?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<bool> {
        let path = self.path(name)?;
        let existed = path.exists();
        if existed {
            fs::remove_file(path)?;
        }
        Ok(existed)
    }
}

pub fn node_identity_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("identity").join("node-client")
}

/// Load (or create on first use) the client identity this node uses on peers.
pub fn load_or_create_node_identity(data_dir: &Path) -> Result<Identity> {
    let dir = node_identity_dir(data_dir);
    if dir.join("identity.key").exists() {
        return Identity::load(&dir);
    }
    let identity = Identity::generate_client();
    identity.save(&dir)?;
    Ok(identity)
}

/// Client config for talking to a peer. Node links never decrypt data, so the
/// encryption key is a throwaway value that is never used.
pub fn peer_client_config(
    data_dir: &Path,
    record: &PeerRecord,
    bootstrap_secret: Option<EnrollmentSecret>,
) -> Result<BackupSasConfig> {
    let identity = load_or_create_node_identity(data_dir)?;
    let mut cfg = BackupSasConfig::from_descriptor(
        &record.descriptor,
        identity,
        record.repository.clone(),
        BackupEncryptionKey::new([0u8; 32]),
    )?;
    if let Some(secret) = bootstrap_secret {
        cfg = cfg.with_bootstrap_secret(secret);
    }
    Ok(cfg)
}

/// Enroll this node on a peer (whose operator issued a `node` secret) and
/// persist the link.
pub async fn add_peer(
    data_dir: &Path,
    name: &str,
    descriptor: ConnectDescriptor,
    repository: &str,
    secret: EnrollmentSecret,
) -> Result<PeerRecord> {
    descriptor.verify()?;
    if !descriptor.repositories.iter().any(|r| r == repository) {
        return Err(BackupSasError::RepositoryNotFound(format!(
            "{repository} (peer offers {:?})",
            descriptor.repositories
        )));
    }
    let record = PeerRecord {
        name: name.to_string(),
        descriptor,
        repository: repository.to_string(),
        added_at: backupsas_core::crypto::timestamp_now(),
    };
    let cfg = peer_client_config(data_dir, &record, Some(secret))?;
    let session = BackupSasClient::new(cfg).authenticate().await?;
    session.close().await?;
    PeerStore::open(data_dir)?.save(&record)?;
    Ok(record)
}
