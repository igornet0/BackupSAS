use crate::error::{BackupSasError, Result};
use crate::id::SessionId;
use crate::keys::{PublicKey, SIGNATURE_LEN, SecretKey};
use crate::session::SessionKeys;
use ed25519_dalek::{Signature, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;

pub const CLOCK_SKEW_SECS: i64 = 5 * 60;
pub const SESSION_INFO: &[u8] = b"backupsas-session-v2";

pub fn sign(secret: &SecretKey, message: &[u8]) -> [u8; SIGNATURE_LEN] {
    secret.signing_key().sign(message).to_bytes()
}

pub fn verify(public: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != SIGNATURE_LEN {
        return Err(BackupSasError::Auth("signature must be 64 bytes".into()));
    }
    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    public
        .verifying_key()?
        .verify(message, &sig)
        .map_err(|_| BackupSasError::Auth("invalid signature".into()))
}

pub fn proof_message(nonce: &[u8], participant_id: &str, timestamp: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(nonce.len() + participant_id.len() + 8);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(participant_id.as_bytes());
    msg.extend_from_slice(&timestamp.to_le_bytes());
    msg
}

pub fn timestamp_now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}

pub fn timestamp_is_fresh(timestamp: u64) -> bool {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ts = timestamp as i64;
    (now - ts).abs() <= CLOCK_SKEW_SECS
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && constant_time_eq::constant_time_eq(a, b)
}

pub fn derive_session_keys(
    session_id: &SessionId,
    client_signature: &[u8],
    server_signature: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<SessionKeys> {
    let mut material = Vec::new();
    material.extend_from_slice(client_signature);
    material.extend_from_slice(server_signature);
    material.extend_from_slice(client_nonce);
    material.extend_from_slice(server_nonce);

    let salt = session_id.to_string();
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &material);
    let mut okm = [0u8; 64];
    hk.expand(SESSION_INFO, &mut okm)
        .map_err(|e| BackupSasError::Session(format!("hkdf: {e}")))?;
    let mut mac_key = [0u8; 32];
    let mut confirm_key = [0u8; 32];
    mac_key.copy_from_slice(&okm[..32]);
    confirm_key.copy_from_slice(&okm[32..]);
    Ok(SessionKeys {
        mac_key,
        confirm_key,
    })
}

pub fn random_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::SessionId;

    #[test]
    fn sign_verify_roundtrip() {
        let secret = SecretKey::generate();
        let public = secret.public_key();
        let msg = b"nonce||cli_01||123";
        let sig = sign(&secret, msg);
        verify(&public, msg, &sig).unwrap();
        assert!(verify(&public, b"tampered", &sig).is_err());
    }

    #[test]
    fn session_keys_are_deterministic() {
        let id = SessionId::new();
        let a = derive_session_keys(&id, b"csig", b"ssig", b"cn", b"sn").unwrap();
        let b = derive_session_keys(&id, b"csig", b"ssig", b"cn", b"sn").unwrap();
        assert_eq!(a.mac_key, b.mac_key);
        assert_eq!(a.confirm_key, b.confirm_key);
        let c = derive_session_keys(&id, b"other", b"ssig", b"cn", b"sn").unwrap();
        assert_ne!(a.mac_key, c.mac_key);
    }

    #[test]
    fn timestamp_window() {
        assert!(timestamp_is_fresh(timestamp_now()));
        assert!(!timestamp_is_fresh(0));
    }
}
