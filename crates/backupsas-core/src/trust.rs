use crate::error::Result;
use crate::id::ParticipantId;
use crate::keys::{Fingerprint, PublicKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    pub id: ParticipantId,
    pub public_key: PublicKey,
    pub fingerprint: Fingerprint,
    pub repositories: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub enrolled_at: OffsetDateTime,
}

impl TrustedPeer {
    pub fn new(id: ParticipantId, public_key: PublicKey, repositories: Vec<String>) -> Self {
        Self {
            fingerprint: public_key.fingerprint(),
            id,
            public_key,
            repositories,
            enrolled_at: OffsetDateTime::now_utc(),
        }
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
