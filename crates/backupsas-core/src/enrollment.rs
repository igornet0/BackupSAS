use crate::crypto::{constant_time_eq, random_nonce};
use crate::error::{BackupSasError, Result};
use crate::hash::hash_bytes;
use crate::id::ClientId;
use crate::keys::PublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::ZeroizeOnDrop;

pub const ENROLLMENT_PREFIX: &str = "bs_enroll_";

#[derive(Clone, ZeroizeOnDrop)]
pub struct EnrollmentSecret(String);

impl EnrollmentSecret {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(format!("{ENROLLMENT_PREFIX}{}", hex::encode(bytes)))
    }

    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if !s.starts_with(ENROLLMENT_PREFIX) {
            return Err(BackupSasError::Enrollment(
                "enrollment secret must start with bs_enroll_".into(),
            ));
        }
        Ok(Self(s))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn hash(&self) -> String {
        hash_bytes(self.0.as_bytes())
    }

    pub fn proof(&self, nonce: &[u8]) -> String {
        let mut data = Vec::with_capacity(nonce.len() + self.0.len());
        data.extend_from_slice(nonce);
        data.extend_from_slice(self.0.as_bytes());
        hash_bytes(&data)
    }
}

impl std::fmt::Debug for EnrollmentSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrollmentSecret([redacted])")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub secret_hash: String,
}

impl EnrollmentRecord {
    pub fn from_secret(secret: &EnrollmentSecret) -> Self {
        Self {
            secret_hash: secret.hash(),
        }
    }

    pub fn matches(&self, secret: &EnrollmentSecret) -> bool {
        constant_time_eq(self.secret_hash.as_bytes(), secret.hash().as_bytes())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = format!("secret_hash = \"{}\"\n", self.secret_hash);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let mut secret_hash = None;
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("secret_hash") {
                let v = v.trim().trim_start_matches('=').trim().trim_matches('"');
                secret_hash = Some(v.to_string());
            }
        }
        Ok(Self {
            secret_hash: secret_hash.ok_or_else(|| {
                BackupSasError::Enrollment("enrollment.secret missing hash".into())
            })?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PendingEnrollment {
    pub client_id: ClientId,
    pub public_key: PublicKey,
    pub nonce: [u8; 32],
}

impl PendingEnrollment {
    pub fn new(client_id: ClientId, public_key: PublicKey) -> Self {
        Self {
            client_id,
            public_key,
            nonce: random_nonce(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hash_matches() {
        let secret = EnrollmentSecret::generate();
        let record = EnrollmentRecord::from_secret(&secret);
        assert!(record.matches(&secret));
        let other = EnrollmentSecret::generate();
        assert!(!record.matches(&other));
    }
}
