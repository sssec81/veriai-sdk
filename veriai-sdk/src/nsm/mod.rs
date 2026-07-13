pub mod schema;

#[cfg(feature = "mock-hardware")]
pub mod mock;

#[cfg(feature = "real-hardware")]
pub mod real;

#[cfg(feature = "mock-hardware")]
pub use mock::get_attestation_document;

#[cfg(feature = "real-hardware")]
pub use real::get_attestation_document;

