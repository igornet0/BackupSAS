use crate::error::{BackupSasError, Result};
use crate::id::ParticipantId;
use crate::keys::{Fingerprint, PublicKey, SIGNATURE_LEN, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Long-lived Ed25519 identity. The secret key never leaves the device.
pub struct Identity {
    pub id: ParticipantId,
    pub public_key: PublicKey,
    secret_key: SecretKey,
}

impl Identity {
    pub fn generate_server() -> Self {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        Self {
            id: ParticipantId::Server(crate::id::ServerId::new()),
            public_key,
            secret_key,
        }
    }

    pub fn generate_client() -> Self {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        Self {
            id: ParticipantId::Client(crate::id::ClientId::new()),
            public_key,
            secret_key,
        }
    }

    pub fn from_parts(id: ParticipantId, secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            id,
            public_key,
            secret_key,
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        crate::crypto::sign(&self.secret_key, message)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        let public = IdentityPublic {
            id: self.id,
            public_key: self.public_key,
        };
        let toml = toml_public(&public)?;
        fs::write(dir.join("identity.toml"), toml)?;
        let key_path = dir.join("identity.key");
        fs::write(
            key_path.as_path(),
            hex::encode(self.secret_key.export_bytes()),
        )?;
        let mut perms = fs::metadata(&key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_path, perms)?;
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let text = fs::read_to_string(dir.join("identity.toml"))?;
        let public: IdentityPublic = parse_public(&text)?;
        let hex_key = fs::read_to_string(dir.join("identity.key"))?;
        let bytes = hex::decode(hex_key.trim())
            .map_err(|e| BackupSasError::Auth(format!("identity.key: {e}")))?;
        if bytes.len() != 32 {
            return Err(BackupSasError::Auth("identity.key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let secret_key = SecretKey::from_bytes(arr);
        if secret_key.public_key() != public.public_key {
            return Err(BackupSasError::Auth(
                "identity.key does not match identity.toml public key".into(),
            ));
        }
        Ok(Self {
            id: public.id,
            public_key: public.public_key,
            secret_key,
        })
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("secret_key", &self.secret_key)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityPublic {
    id: ParticipantId,
    public_key: PublicKey,
}

fn toml_public(public: &IdentityPublic) -> Result<String> {
    // Keep identity.toml tiny and serde-friendly without adding toml to core if possible.
    // We write a minimal TOML by hand to avoid a toml dependency in core.
    Ok(format!(
        "id = \"{}\"\npublic_key = \"{}\"\n",
        public.id, public.public_key
    ))
}

fn parse_public(text: &str) -> Result<IdentityPublic> {
    let mut id = None;
    let mut public_key = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        match k.trim() {
            "id" => id = Some(v.parse()?),
            "public_key" => public_key = Some(PublicKey::from_wire(v)?),
            _ => {}
        }
    }
    Ok(IdentityPublic {
        id: id.ok_or_else(|| BackupSasError::Auth("identity.toml missing id".into()))?,
        public_key: public_key
            .ok_or_else(|| BackupSasError::Auth("identity.toml missing public_key".into()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile_dir();
        let id = Identity::generate_client();
        id.save(&dir).unwrap();
        let loaded = Identity::load(&dir).unwrap();
        assert_eq!(id.id, loaded.id);
        assert_eq!(id.public_key, loaded.public_key);
        let msg = b"hello";
        crate::crypto::verify(&loaded.public_key, msg, &id.sign(msg)).unwrap();
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bsas-id-{}", crate::id::ClientId::new()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
