use sha2::Digest;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use veriai_core::hashing::compute_model_hash;

#[test]
fn test_empty_file_hash() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("empty.bin");
    File::create(&file_path).unwrap();

    let hash = compute_model_hash(&file_path).expect("Failed to compute hash");
    // SHA256 of empty bytes
    let expected = sha2::Sha256::digest([]);
    assert_eq!(hash, expected.as_ref());
}

#[test]
fn test_small_file_hash() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("small.bin");
    let mut file = File::create(&file_path).unwrap();
    file.write_all(b"hello veriai").unwrap();

    let hash = compute_model_hash(&file_path).expect("Failed to compute hash");
    // SHA256 of "hello veriai"
    let expected = sha2::Sha256::digest(b"hello veriai");
    assert_eq!(hash, expected.as_ref());
}

#[test]
fn test_large_file_merkle_root() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("large.bin");
    let mut file = File::create(&file_path).unwrap();

    // Write exactly 10MB of data (needs multiple 4MB chunks)
    let chunk_a = vec![0x11u8; 4 * 1024 * 1024];
    let chunk_b = vec![0x22u8; 4 * 1024 * 1024];
    let chunk_c = vec![0x33u8; 2 * 1024 * 1024];
    file.write_all(&chunk_a).unwrap();
    file.write_all(&chunk_b).unwrap();
    file.write_all(&chunk_c).unwrap();
    drop(file);

    let root = compute_model_hash(&file_path).expect("Failed to compute root");

    // Manually reconstruct expected Merkle root
    use sha2::{Digest, Sha256};
    let h0 = Sha256::digest(&chunk_a);
    let h1 = Sha256::digest(&chunk_b);
    let h2 = Sha256::digest(&chunk_c);

    // Level 1: hash(h0 || h1), hash(h2 || h2)
    let mut hasher = Sha256::new();
    hasher.update(h0);
    hasher.update(h1);
    let h01 = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(h2);
    hasher.update(h2);
    let h22 = hasher.finalize();

    // Level 2 (Root): hash(h01 || h22)
    let mut hasher = Sha256::new();
    hasher.update(h01);
    hasher.update(h22);
    let expected_root: [u8; 32] = hasher.finalize().into();

    assert_eq!(root, expected_root);
}
