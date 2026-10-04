use crate::error::Result;
use crate::id::ParticipantId;
use crate::keys::{Fingerprint, PublicKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Role of an enrolled identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerKind {
    /// A database (e.g. Avrora) that owns and encrypts backups.
    #[default]
    Database,
    /// Another BackupSAS node allowed to push transfers here.
    Node,
}

impl PeerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Node => "node",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "database" => Ok(Self::Database),
            "node" => Ok(Self::Node),
            other => Err(crate::error::BackupSasError::Enrollment(format!(
                "unknown peer kind `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub id: ParticipantId,
    pub public_key: PublicKey,
    pub fingerprint: Fingerprint,
    pub repositories: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,
    #[serde(default)]
    pub kind: PeerKind,
    /// Set when trust was delegated by another node during a transfer
    /// instead of a direct enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
}

impl TrustedPeer {
    pub fn new(id: ParticipantId, public_key: PublicKey, repositories: Vec<String>) -> Self {
        Self {
            fingerprint: public_key.fingerprint(),
            id,
            public_key,
            repositories,
            enrolled_at: OffsetDateTime::now_utc(),
            kind: PeerKind::Database,
            delegated_by: None,
        }
    }

    pub fn with_kind(mut self, kind: PeerKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn delegated(mut self, by: impl Into<String>) -> Self {
        self.delegated_by = Some(by.into());
        self
    }

    pub fn allows_repo(&self, name: &str) -> bool {
        self.repositories.iter().any(|r| r == name)
    }
}

pub fn pin_matches(expected: &PublicKey, actual: &PublicKey) -> Result<()> {
    if expected != actual {
        return Err(crate::error::BackupSasError::TrustPinMismatch {
            expected: expected.to_wire(),
            actual: actual.to_wire(),
        });
    }
    Ok(())
}
