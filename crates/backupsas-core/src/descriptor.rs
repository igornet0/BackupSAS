//! Public connection descriptor (`backupsas-connect/v1`).
//!
//! A node publishes this JSON so a database (Avrora) or another node can pin
//! its identity and reach it. It contains no secrets: the one-time enrollment
//! secret is handed over separately.

use crate::canonical::canonical_bytes;
use crate::error::{BackupSasError, Result};
use crate::id::ServerId;
use crate::identity::Identity;
use crate::keys::{Fingerprint, PublicKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DESCRIPTOR_FORMAT: &str = "backupsas-connect/v1";
const SIGNING_DOMAIN: &[u8] = b"backupsas-connect-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectDescriptor {
    pub format: String,
    pub server_id: ServerId,
    pub public_key: PublicKey,
    pub fingerprint: String,
    pub endpoints: Vec<String>,
    pub server_name: String,
    pub ca_cert_pem: String,
    pub repositories: Vec<String>,
    pub features: Vec<String>,
    /// Unix seconds.
    pub issued_at: u64,
    /// Hex Ed25519 signature over the canonical JSON without this field.
    #[serde(default)]
    pub signature: String,
}

impl ConnectDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_id: ServerId,
        public_key: PublicKey,
        endpoints: Vec<String>,
        server_name: impl Into<String>,
        ca_cert_pem: impl Into<String>,
        repositories: Vec<String>,
        features: Vec<String>,
    ) -> Self {
        Self {
            format: DESCRIPTOR_FORMAT.to_string(),
            server_id,
            fingerprint: public_key.fingerprint().as_str().to_string(),
            public_key,
            endpoints,
            server_name: server_name.into(),
            ca_cert_pem: ca_cert_pem.into(),
            repositories,
            features,
            issued_at: crate::crypto::timestamp_now(),
            signature: String::new(),
        }
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        if let Some(map) = value.as_object_mut() {
            map.remove("signature");
        }
        let mut out = SIGNING_DOMAIN.to_vec();
        out.extend_from_slice(&canonical_bytes(&value)?);
        Ok(out)
    }

    /// Sign with the node identity. The identity must match `public_key`.
    pub fn sign(mut self, identity: &Identity) -> Result<Self> {
        if identity.public_key != self.public_key {
            return Err(BackupSasError::Auth(
                "descriptor public key does not match signing identity".into(),
            ));
        }
        self.signature.clear();
        let sig = identity.sign(&self.signing_bytes()?);
        self.signature = hex::encode(sig);
        Ok(self)
    }

    /// Check format, fingerprint and the self-signature.
    pub fn verify(&self) -> Result<()> {
        if self.format != DESCRIPTOR_FORMAT {
            return Err(BackupSasError::Protocol(format!(
                "unsupported descriptor format `{}`",
                self.format
            )));
        }
        if Fingerprint::from_public_key(&self.public_key).as_str() != self.fingerprint {
            return Err(BackupSasError::Auth(
                "descriptor fingerprint mismatch".into(),
            ));
        }
        if self.endpoints.is_empty() {
            return Err(BackupSasError::Protocol(
                "descriptor has no endpoints".into(),
            ));
        }
        let sig = hex::decode(&self.signature)
            .map_err(|e| BackupSasError::Auth(format!("descriptor signature hex: {e}")))?;
        crate::crypto::verify(&self.public_key, &self.signing_bytes()?, &sig)
    }

    /// Verify and additionally require the key to equal a pinned key.
    pub fn verify_pinned(&self, pinned: &PublicKey) -> Result<()> {
        self.verify()?;
        crate::trust::pin_matches(pinned, &self.public_key)
    }

    pub fn has_feature(&self, name: &str) -> bool {
        self.features.iter().any(|f| f == name)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(text: &str) -> Result<Self> {
        Ok(serde_json::from_str(text)?)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::from_json(&text)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_json_pretty()?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ParticipantId;

    fn signed() -> (ConnectDescriptor, Identity) {
        let identity = Identity::generate_server();
        let ParticipantId::Server(sid) = identity.id else {
            unreachable!()
        };
        let d = ConnectDescriptor::new(
            sid,
            identity.public_key,
            vec!["10.0.0.5:7420".into()],
            "localhost",
            "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
            vec!["avrora-prod".into()],
            vec!["list".into()],
        )
        .sign(&identity)
        .unwrap();
        (d, identity)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (d, identity) = signed();
        d.verify().unwrap();
        let back = ConnectDescriptor::from_json(&d.to_json_pretty().unwrap()).unwrap();
        back.verify_pinned(&identity.public_key).unwrap();
    }

    #[test]
    fn tampered_endpoint_rejected() {
        let (mut d, _) = signed();
        d.endpoints = vec!["evil:7420".into()];
        assert!(d.verify().is_err());
    }

    #[test]
    fn swapped_key_rejected() {
        let (mut d, _) = signed();
        let other = Identity::generate_server();
        d.public_key = other.public_key;
        assert!(d.verify().is_err());
        d.fingerprint = other.fingerprint().as_str().to_string();
        assert!(d.verify().is_err());
    }

    #[test]
    fn pin_mismatch_rejected() {
        let (d, _) = signed();
        let other = Identity::generate_server();
        assert!(d.verify_pinned(&other.public_key).is_err());
    }
}
