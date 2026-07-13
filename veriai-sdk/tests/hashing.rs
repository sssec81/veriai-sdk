use veriai_sdk::hashing::compute_model_hash;
use std::io::Write;
use tempfile::NamedTempFile;
use sha2::{Sha256, Digest};

#[test]
fn test_empty_file_hash() {
    let temp_file = NamedTempFile::new().unwrap();
    let root = compute_model_hash(temp_file.path()).unwrap();
    
    // Hash of empty slice
    let expected: [u8; 32] = Sha256::digest(&[]).into();
    assert_eq!(root, expected);
}

#[test]
fn test_small_file_hash() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let data = b"Hello, VeriAI Merkle engine!";
    temp_file.write_all(data).unwrap();
    temp_file.flush().unwrap();

    let root = compute_model_hash(temp_file.path()).unwrap();

    // Single chunk (<4MB) should just be the hash of the chunk data itself
    let expected: [u8; 32] = Sha256::digest(data).into();
    assert_eq!(root, expected);
}


#[test]
fn test_large_file_merkle_root() {
    let mut temp_file = NamedTempFile::new().unwrap();
    
    // Create a 6MB file to force exactly two chunks: 4MB chunk + 2MB chunk
    let chunk1_data = vec![0x11u8; 4 * 1024 * 1024];
    let chunk2_data = vec![0x22u8; 2 * 1024 * 1024];
    
    temp_file.write_all(&chunk1_data).unwrap();
    temp_file.write_all(&chunk2_data).unwrap();
    temp_file.flush().unwrap();

    let root = compute_model_hash(temp_file.path()).unwrap();

    // Compute expected hashes
    let hash1 = Sha256::digest(&chunk1_data);
    let hash2 = Sha256::digest(&chunk2_data);

    let mut expected_hasher = Sha256::new();
    expected_hasher.update(hash1);
    expected_hasher.update(hash2);
    let expected: [u8; 32] = expected_hasher.finalize().into();

    assert_eq!(root, expected);
}

#[test]
fn test_caching_behavior() {
    let mut temp_file = NamedTempFile::new().unwrap();
    let data = b"Cache test content";
    temp_file.write_all(data).unwrap();
    temp_file.flush().unwrap();

    // Run first time to compute and cache
    let hash_first = compute_model_hash(temp_file.path()).unwrap();

    // Run second time (should read from cache)
    let hash_second = compute_model_hash(temp_file.path()).unwrap();

    assert_eq!(hash_first, hash_second);
}
