use crate::chunker::Chunk;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use backupsas_core::{BackupSasError, Result, hash_bytes};

pub const NONCE_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    pub sequence: u32,
    pub payload: Vec<u8>,
    pub hash: String,
}

impl EncryptedChunk {
    pub fn from_ciphertext(sequence: u32, payload: Vec<u8>) -> Self {
        let hash = hash_bytes(&payload);
        Self {
            sequence,
            payload,
            hash,
        }
    }
}

pub trait ChunkEncryptor {
    fn encrypt(&self, sequence: u32, plaintext: &[u8]) -> Result<EncryptedChunk>;
}

/// AES-256-GCM chunk cipher. The key schedule is wiped on drop (`aes`
/// `zeroize` feature); no `Debug` impl so the key cannot be printed.
pub struct Aes256GcmEncryptor {
    cipher: Aes256Gcm,
}

impl Aes256GcmEncryptor {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }

    pub fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < NONCE_LEN {
            return Err(BackupSasError::Other("ciphertext too short".into()));
        }
        let nonce = Nonce::from_slice(&payload[..NONCE_LEN]);
        self.cipher
            .decrypt(nonce, &payload[NONCE_LEN..])
            .map_err(|e| BackupSasError::Other(format!("decrypt: {e}")))
    }

    pub fn encrypt_chunks(&self, chunks: &[Chunk]) -> Result<Vec<EncryptedChunk>> {
        chunks
            .iter()
            .map(|c| self.encrypt(c.sequence, &c.plaintext))
            .collect()
    }
}

impl ChunkEncryptor for Aes256GcmEncryptor {
    fn encrypt(&self, sequence: u32, plaintext: &[u8]) -> Result<EncryptedChunk> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| BackupSasError::Other(format!("encrypt: {e}")))?;
        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        Ok(EncryptedChunk::from_ciphertext(sequence, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let enc = Aes256GcmEncryptor::new(&[7u8; 32]);
        let chunk = enc.encrypt(0, b"secret-backup").unwrap();
        assert!(chunk.hash.starts_with("blake3:"));
        let plain = enc.decrypt(&chunk.payload).unwrap();
        assert_eq!(plain, b"secret-backup");
    }
}
