use backupsas_core::{BackupSasError, ClientId, Result, TrustedPeer};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TrustStore {
    dir: PathBuf,
    peers: HashMap<ClientId, TrustedPeer>,
}

impl TrustStore {
    pub fn load(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let mut peers = HashMap::new();
        for item in fs::read_dir(dir)? {
            let item = item?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = fs::read_to_string(&path)?;
            let peer: TrustedPeer = toml::from_str(&text)
                .map_err(|e| BackupSasError::Serde(format!("{}: {e}", path.display())))?;
            if let backupsas_core::ParticipantId::Client(id) = peer.id {
                peers.insert(id, peer);
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            peers,
        })
    }

    pub fn get(&self, id: &ClientId) -> Option<&TrustedPeer> {
        self.peers.get(id)
    }

    pub fn list(&self) -> Vec<TrustedPeer> {
        self.peers.values().cloned().collect()
    }

    pub fn insert(&mut self, peer: TrustedPeer) -> Result<()> {
        let backupsas_core::ParticipantId::Client(id) = peer.id else {
            return Err(BackupSasError::Enrollment(
                "only client identities can be enrolled".into(),
            ));
        };
        let text =
            toml::to_string_pretty(&peer).map_err(|e| BackupSasError::Serde(e.to_string()))?;
        fs::write(self.dir.join(format!("{id}.toml")), text)?;
        self.peers.insert(id, peer);
        Ok(())
    }

    pub fn revoke(&mut self, id: &ClientId) -> Result<bool> {
        let path = self.dir.join(format!("{id}.toml"));
        let existed = path.exists();
        if existed {
            fs::remove_file(path)?;
        }
        self.peers.remove(id);
        Ok(existed)
    }
}
