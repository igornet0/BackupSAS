use crate::crypto::{proof_message, timestamp_is_fresh, timestamp_now, verify};
use crate::error::{BackupSasError, Result};
use crate::keys::{PublicKey, SIGNATURE_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 32],
}

impl Challenge {
    pub fn new(nonce: [u8; 32]) -> Self {
        Self { nonce }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    pub timestamp: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl AuthProof {
    pub fn create(identity: &crate::identity::Identity, nonce: &[u8]) -> Self {
        let timestamp = timestamp_now();
        let message = proof_message(nonce, &identity.id.to_string(), timestamp);
        Self {
            timestamp,
            signature: identity.sign(&message),
        }
    }

    pub fn verify(&self, public: &PublicKey, participant_id: &str, nonce: &[u8]) -> Result<()> {
        if !timestamp_is_fresh(self.timestamp) {
            return Err(BackupSasError::Auth(
                "proof timestamp outside clock window".into(),
            ));
        }
        let message = proof_message(nonce, participant_id, self.timestamp);
        verify(public, &message, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_nonce;
    use crate::identity::Identity;

    #[test]
    fn proof_of_possession() {
        let identity = Identity::generate_client();
        let nonce = random_nonce();
        let proof = AuthProof::create(&identity, &nonce);
        proof
            .verify(&identity.public_key, &identity.id.to_string(), &nonce)
            .unwrap();

        let other = Identity::generate_client();
        assert!(
            proof
                .verify(&other.public_key, &identity.id.to_string(), &nonce)
                .is_err()
        );
    }
}
