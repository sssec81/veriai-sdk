use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_attestation::AttestationProvider;
use veriai_types::VeriClaims;
use veriai_types::error::VerifyError;

/// Generates cryptographically signed receipts binding model identity, hardware attestation, and input/output hashes.
pub struct ReceiptGenerator {
    provider: Arc<dyn AttestationProvider>,
    // ed25519-dalek enables zeroization for SigningKey through its default `std` feature.
    signing_key: SigningKey,
    sequence_num: AtomicU64,
    generation_lock: tokio::sync::Mutex<()>,
}

impl ReceiptGenerator {
    /// Create a new generator with a randomly generated ephemeral Ed25519 signing key
    pub fn new(provider: Arc<dyn AttestationProvider>) -> Self {
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self {
            provider,
            signing_key,
            sequence_num: AtomicU64::new(0),
            generation_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Explicit constructor using an existing signing key (useful for testing)
    pub fn with_key(provider: Arc<dyn AttestationProvider>, signing_key: SigningKey) -> Self {
        Self {
            provider,
            signing_key,
            sequence_num: AtomicU64::new(0),
            generation_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Returns the raw 32-byte public key of the enclave's ephemeral keypair
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Compute the REPORTDATA binding value for the current ephemeral public key:
    /// SHA-512(0x01 || "VeriAI-KeyBind-v1" || Ed25519_PubKey_32bytes)
    pub fn compute_report_data(&self) -> [u8; 64] {
        let pubkey_bytes = self.public_key_bytes();
        let mut hasher = Sha512::new();
        hasher.update([0x01]);
        hasher.update(b"VeriAI-KeyBind-v1");
        hasher.update(pubkey_bytes);
        hasher.finalize().into()
    }

    /// Generates a signed COSE_Sign1 receipt wrapping custom CWT claims
    pub async fn generate_receipt(
        &self,
        model_hash: [u8; 32],
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        client_nonce: [u8; 32],
    ) -> Result<Vec<u8>, VerifyError> {
        // Preserve completion-order monotonicity for callers sharing a
        // generator. Atomic allocation alone cannot prevent task reordering.
        let _generation_guard = self.generation_lock.lock().await;
        let pubkey_bytes = self.public_key_bytes();
        let report_data = self.compute_report_data();

        // 1. Get signed attestation document from the NSM binding it to our key
        let attestation_report = self
            .provider
            .generate(Some(&report_data), Some(&client_nonce), Some(&pubkey_bytes))
            .await
            .map_err(|e| VerifyError::Attestation(e.to_string()))?;
        // Do not consume a sequence value when attestation generation fails.
        // Exhaustion is terminal rather than silently wrapping to zero.
        let sequence_num = self
            .sequence_num
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_add(1)
            })
            .map_err(|_| VerifyError::SequenceNumberExhausted)?;

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VerifyError::InvalidAttestationDocument(e.to_string()))?
            .as_secs() as i64;

        // 2. Build VeriClaims
        let claims = VeriClaims {
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            sequence_num,
            attestation_report,
            attestation_type: 3, // 3 = Nitro
            attestation_timestamp: now_sec,
            sdk_version: env!("CARGO_PKG_VERSION").to_string(),
            enclave_pubkey: pubkey_bytes,
        };

        let payload = claims
            .to_binary()
            .map_err(|_| VerifyError::MalformedReceipt)?;

        // 3. Wrap in COSE_Sign1
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .content_type("application/cwt".to_string())
            .build();

        let mut cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .build();

        // 4. Sign with the ephemeral Ed25519 key
        let tbs = cose_sign1.tbs_data(&[]);
        let signature = self.signing_key.sign(&tbs);
        cose_sign1.signature = signature.to_bytes().to_vec();

        cose_sign1
            .to_vec()
            .map_err(|_| VerifyError::MalformedReceipt)
    }
}

#[cfg(test)]
mod tests {
    use super::ReceiptGenerator;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use veriai_attestation::mock::MockAttestationProvider;
    use veriai_types::error::VerifyError;

    #[test]
    fn independent_generators_use_independent_keys() {
        let provider = Arc::new(MockAttestationProvider::new());
        let first = ReceiptGenerator::new(provider.clone());
        let second = ReceiptGenerator::new(provider);
        assert_ne!(first.public_key_bytes(), second.public_key_bytes());
    }

    #[tokio::test]
    async fn sequence_exhaustion_fails_closed() {
        let generator = ReceiptGenerator::new(Arc::new(MockAttestationProvider::new()));
        generator.sequence_num.store(u64::MAX, Ordering::SeqCst);
        let result = generator
            .generate_receipt([1; 32], [2; 32], [3; 32], [4; 32])
            .await;
        assert_eq!(result, Err(VerifyError::SequenceNumberExhausted));
    }
}
