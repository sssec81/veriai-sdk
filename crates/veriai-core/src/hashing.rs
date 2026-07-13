use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::SystemTime;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CacheEntry {
    file_size: u64,
    modified_time_secs: u64,
    modified_time_nanos: u32,
    merkle_root: [u8; 32],
}

/// Computes the SHA-256 Merkle root of a file using 4MB chunks.
/// Uses an on-disk cache located in the system temporary directory to avoid re-hashing large files if they haven't changed.
pub fn compute_model_hash<P: AsRef<Path>>(path: P) -> io::Result<[u8; 32]> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();
    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let duration = modified.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let mtime_secs = duration.as_secs();
    let mtime_nanos = duration.subsec_nanos();

    // Try loading from cache
    let cache_dir = std::env::temp_dir().join("veriai_cache");
    let cache_file = cache_dir.join("model_hashes.json");
    
    if let Ok(cache) = load_cache(&cache_file) {
        let path_str = path.to_string_lossy().into_owned();
        if let Some(entry) = cache.get(&path_str) {
            if entry.file_size == file_size 
                && entry.modified_time_secs == mtime_secs 
                && entry.modified_time_nanos == mtime_nanos 
            {
                return Ok(entry.merkle_root);
            }
        }
    }

    // Recompute hash
    let root = hash_file_merkle(path)?;

    // Update cache
    let entry = CacheEntry {
        file_size,
        modified_time_secs: mtime_secs,
        modified_time_nanos: mtime_nanos,
        merkle_root: root,
    };
    let _ = save_cache(&cache_file, path.to_string_lossy().as_ref(), entry);

    Ok(root)
}

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
        let hash: [u8; 32] = Sha256::digest(&[]).into();
        return Ok(hash);
    }

    // Compute Merkle root from leaves
    let mut current_level = leaves;
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
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

fn load_cache(cache_file: &Path) -> io::Result<HashMap<String, CacheEntry>> {
    if !cache_file.exists() {
        return Ok(HashMap::new());
    }
    let file = File::open(cache_file)?;
    let cache = serde_json::from_reader(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(cache)
}

fn save_cache(cache_file: &Path, key: &str, entry: CacheEntry) -> io::Result<()> {
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut cache = load_cache(cache_file).unwrap_or_default();
    cache.insert(key.to_string(), entry);

    let file = File::create(cache_file)?;
    serde_json::to_writer_pretty(file, &cache)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(())
}
