use crate::error::{BackupSasError, Result};

pub const HASH_PREFIX: &str = "blake3:";

pub fn hash_bytes(data: &[u8]) -> String {
    format!("{HASH_PREFIX}{}", blake3::hash(data).to_hex())
}

pub fn parse_hash_bytes(hash: &str) -> Result<[u8; 32]> {
    let hex = hash.strip_prefix(HASH_PREFIX).unwrap_or(hash);
    let bytes =
        hex::decode(hex).map_err(|e| BackupSasError::InvalidManifest(format!("hash: {e}")))?;
    if bytes.len() != 32 {
        return Err(BackupSasError::InvalidManifest(format!(
            "hash must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn verify_hash(data: &[u8], expected: &str) -> Result<()> {
    let actual = hash_bytes(data);
    if actual != expected {
        return Err(BackupSasError::ChunkHashMismatch {
            seq: 0,
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable() {
        let a = hash_bytes(b"hello");
        let b = hash_bytes(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with("blake3:"));
        assert_ne!(a, hash_bytes(b"world"));
    }
}
