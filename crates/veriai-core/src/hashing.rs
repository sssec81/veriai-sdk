use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB

/// Computes the SHA-256 Merkle root of a file using 4MB chunks.
///
/// The model is read on every call. Receipt generation and verification must not
/// trust a metadata-only cache for model identity.
pub fn compute_model_hash<P: AsRef<Path>>(path: P) -> io::Result<[u8; 32]> {
    hash_file_merkle(path.as_ref())
}

/// Computes the SHA-256 Merkle root of a file using 4MB chunks.
///
/// # Security Note
/// This function duplicates the last node when the leaf count is odd (the same pattern
/// as Bitcoin CVE-2012-2459). Since this hash is only used as a single root identifier
/// and inclusion proofs are not exposed, this is low severity. Do NOT build an inclusion-proof
/// feature on top of this function without updating the tree construction to avoid duplicate node collisions.
fn hash_file_merkle(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut leaves = Vec::new();

    loop {
        let mut bytes_read = 0;
        while bytes_read < CHUNK_SIZE {
            let n = file.read(&mut buffer[bytes_read..])?;
            if n == 0 {
                break;
            }
            bytes_read += n;
        }

        if bytes_read == 0 {
            break;
        }

        let mut hasher = Sha256::new();
        hasher.update(&buffer[..bytes_read]);
        let hash: [u8; 32] = hasher.finalize().into();
        leaves.push(hash);

        if bytes_read < CHUNK_SIZE {
            break; // EOF reached
        }
    }

    // If file is empty, hash of empty bytes
    if leaves.is_empty() {
        let hash: [u8; 32] = Sha256::digest([]).into();
        return Ok(hash);
    }

    // Compute Merkle root from leaves
    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut chunks = current_level.chunks_exact(2);

        for chunk in &mut chunks {
            let mut hasher = Sha256::new();
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            next_level.push(hasher.finalize().into());
        }

        let remainder = chunks.remainder();
        if !remainder.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(remainder[0]);
            hasher.update(remainder[0]); // Duplicate odd node
            next_level.push(hasher.finalize().into());
        }

        current_level = next_level;
    }

    Ok(current_level[0])
}
