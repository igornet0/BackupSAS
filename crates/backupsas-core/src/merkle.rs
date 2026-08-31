use crate::error::{BackupSasError, Result};
use crate::hash::{parse_hash_bytes, HASH_PREFIX};

pub const DOMAIN_LEAF: &[u8] = b"backupsas/v1/leaf";
pub const DOMAIN_NODE: &[u8] = b"backupsas/v1/node";

/// Merkle leaf: BLAKE3(domain_leaf || u64_be(sequence) || chunk_hash_bytes).
pub fn merkle_leaf(sequence: u32, chunk_hash_bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_LEAF);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(chunk_hash_bytes);
    *hasher.finalize().as_bytes()
}

/// Internal node: BLAKE3(domain_node || left || right).
pub fn merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_NODE);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// Compute Merkle root over chunk ciphertext hashes (wire form `blake3:<hex>`).
/// Odd levels duplicate the last node.
pub fn merkle_root(chunk_hashes: &[String]) -> Result<String> {
    if chunk_hashes.is_empty() {
        let empty_chunk = blake3::hash(&[]);
        let leaf = merkle_leaf(0, empty_chunk.as_bytes());
        return Ok(format!("{HASH_PREFIX}{}", hex::encode(leaf)));
    }

    let mut level: Vec<[u8; 32]> = chunk_hashes
        .iter()
        .enumerate()
        .map(|(seq, hash)| {
            let bytes = parse_hash_bytes(hash)?;
            Ok(merkle_leaf(seq as u32, &bytes))
        })
        .collect::<Result<Vec<_>>>()?;

    while level.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(merkle_node(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(merkle_node(&level[i], &level[i]));
                i += 1;
            }
        }
        level = next;
    }

    Ok(format!("{HASH_PREFIX}{}", hex::encode(level[0])))
}

pub fn verify_merkle_root(chunk_hashes: &[String], expected_root: &str) -> Result<()> {
    let actual = merkle_root(chunk_hashes)?;
    if actual != expected_root {
        return Err(BackupSasError::InvalidManifest(format!(
            "root_hash mismatch: expected {expected_root}, got {actual}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;

    #[test]
    fn odd_leaf_duplicates_last() {
        let h0 = hash_bytes(b"a");
        let h1 = hash_bytes(b"b");
        let h2 = hash_bytes(b"c");
        let root = merkle_root(&[h0.clone(), h1, h2]).unwrap();
        assert!(root.starts_with("blake3:"));

        let b0 = parse_hash_bytes(&h0).unwrap();
        let b1 = parse_hash_bytes(&hash_bytes(b"b")).unwrap();
        let b2 = parse_hash_bytes(&hash_bytes(b"c")).unwrap();
        let ab = merkle_node(&merkle_leaf(0, &b0), &merkle_leaf(1, &b1));
        let cc = merkle_node(&merkle_leaf(2, &b2), &merkle_leaf(2, &b2));
        let expected = merkle_node(&ab, &cc);
        let wire = format!("blake3:{}", hex::encode(expected));
        assert_eq!(root, wire);
    }

    #[test]
    fn empty_chunks_single_leaf() {
        let root = merkle_root(&[]).unwrap();
        assert!(root.starts_with("blake3:"));
    }
}
