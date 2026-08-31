use crate::error::{BackupSasError, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::ZeroizeOnDrop;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| BackupSasError::Auth(format!("invalid public key: {e}")))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0)
            .map_err(|e| BackupSasError::Auth(format!("invalid public key: {e}")))
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_public_key(self)
    }

    pub fn to_wire(&self) -> String {
        format!("ed25519:{}", hex::encode(self.0))
    }

    pub fn from_wire(s: &str) -> Result<Self> {
        let rest = s.strip_prefix("ed25519:").ok_or_else(|| {
            BackupSasError::Auth("expected `ed25519:` prefix in public key".to_string())
        })?;
        let bytes = hex::decode(rest)
            .map_err(|e| BackupSasError::Auth(format!("invalid public key hex: {e}")))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(BackupSasError::Auth("public key must be 32 bytes".into()));
        }
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(arr)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_wire(&s).map_err(serde::de::Error::custom)
    }
}

/// Ed25519 secret key. Never serialized; zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut rand::rngs::OsRng);
        Self(signing.to_bytes())
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key().verifying_key().to_bytes())
    }

    /// Explicit persistence helper. Do not log the result.
    pub fn export_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub fn from_public_key(key: &PublicKey) -> Self {
        let digest = Sha256::digest(key.as_bytes());
        let hex = hex::encode(digest);
        let grouped = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??").to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        Self(format!("SHA256:{grouped}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.0)
    }
}

/// Per-backup AES-256-GCM data encryption key. Never sent to BackupSAS.
#[derive(Clone, ZeroizeOnDrop)]
pub struct BackupEncryptionKey([u8; 32]);

impl BackupEncryptionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BackupEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupEncryptionKey([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_is_not_serializable_via_debug() {
        let sk = SecretKey::generate();
        assert_eq!(format!("{sk:?}"), "SecretKey([redacted])");
    }

    #[test]
    fn public_key_wire_roundtrip() {
        let pk = SecretKey::generate().public_key();
        let wire = pk.to_wire();
        assert!(wire.starts_with("ed25519:"));
        assert_eq!(PublicKey::from_wire(&wire).unwrap(), pk);
    }
}
