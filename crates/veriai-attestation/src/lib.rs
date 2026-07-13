pub mod mock;

#[cfg(all(feature = "mock-hardware", not(any(test, debug_assertions))))]
compile_error!("Production release builds cannot be compiled with mock-hardware enabled.");

#[cfg(feature = "real-hardware")]
pub mod nitro;

use async_trait::async_trait;
use veriai_types::error::AttestationError;

#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Generate a hardware attestation document enclosing the given user_data, nonce, and public_key.
    async fn generate(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError>;

    /// Verify a hardware attestation document signature and walk its certificate chain up to expected_root.
    async fn verify(&self, doc: &[u8], expected_root: &[u8]) -> Result<bool, AttestationError>;
}
