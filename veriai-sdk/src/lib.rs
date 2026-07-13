// src/lib.rs

#[cfg(all(feature = "mock-hardware", feature = "real-hardware"))]
compile_error!("Features 'mock-hardware' and 'real-hardware' are mutually exclusive.");

#[cfg(all(feature = "mock-hardware", not(debug_assertions), not(feature = "test-mode")))]
compile_error!("Feature 'mock-hardware' is not allowed in release builds. Use --features real-hardware or enable test-mode for test binaries.");

pub mod error;
pub mod nsm;
pub mod hashing;
pub mod receipt;
pub mod verify;


