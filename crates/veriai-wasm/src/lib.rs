use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use veriai_attestation::{AttestationProvider, verify_attestation_doc};
use veriai_core::verify::Verifier;
use veriai_types::VerificationResult;
use veriai_types::error::AttestationError;
use wasm_bindgen::prelude::*;

/// Inputs required to verify one receipt in a browser or other stateless client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    /// Hex or base64 encoded COSE_Sign1 receipt.
    pub receipt: String,
    pub model_hash: String,
    pub input_hash: String,
    pub output_hash: String,
    pub nonce: String,
    pub expected_pcr0: String,
    /// PEM certificate(s) selected by the verifier as trusted roots.
    pub trusted_root_pem: String,
}

struct OfflineNitroProvider;

#[async_trait]
impl AttestationProvider for OfflineNitroProvider {
    fn name(&self) -> &'static str {
        "offline-nitro"
    }

    fn is_hardware_backed(&self) -> bool {
        true
    }

    async fn generate(
        &self,
        _user_data: Option<&[u8]>,
        _nonce: Option<&[u8]>,
        _public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        Err(AttestationError::HardwareUnavailable(
            "the WASM verifier cannot generate attestations".to_string(),
        ))
    }

    async fn verify(&self, doc: &[u8], expected_root: &[u8]) -> Result<bool, AttestationError> {
        Ok(verify_attestation_doc(doc, expected_root, std::time::SystemTime::now()).is_ok())
    }
}

/// Verify one receipt without retaining replay state between calls.
///
/// Callers must enforce nonce uniqueness or keep replay state outside this module.
pub async fn verify(request: VerifyRequest) -> Result<VerificationResult, String> {
    let receipt = decode_receipt(&request.receipt)?;
    let model_hash = decode_hex_32("model_hash", &request.model_hash)?;
    let input_hash = decode_hex_32("input_hash", &request.input_hash)?;
    let output_hash = decode_hex_32("output_hash", &request.output_hash)?;
    let nonce = decode_hex_32("nonce", &request.nonce)?;
    let expected_pcr0 = hex::decode(&request.expected_pcr0)
        .map_err(|error| format!("expected_pcr0 is not valid hex: {error}"))?;
    if expected_pcr0.len() != 48 {
        return Err(format!(
            "expected_pcr0 must be 48 bytes, got {}",
            expected_pcr0.len()
        ));
    }

    let verifier = Verifier::from_pem(
        Arc::new(OfflineNitroProvider),
        &request.trusted_root_pem,
        false,
    )?;
    verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            nonce,
            &expected_pcr0,
        )
        .await
        .map_err(|error| error.to_string())
}

#[wasm_bindgen(js_name = verifyReceipt)]
pub async fn verify_receipt(request: JsValue) -> Result<JsValue, JsValue> {
    let request: VerifyRequest = serde_wasm_bindgen::from_value(request)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let result = verify(request)
        .await
        .map_err(|error| JsValue::from_str(&error))?;
    serde_wasm_bindgen::to_value(&result).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn decode_receipt(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value)
        .or_else(|_| Base64::decode_vec(value))
        .map_err(|_| "receipt must be hex or base64".to_string())
}

fn decode_hex_32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("{name} is not valid hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} must be 32 bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::{VerifyRequest, verify};
    use base64ct::{Base64, Encoding};
    use std::sync::Arc;
    use veriai_attestation::mock::MockAttestationProvider;
    use veriai_core::receipt::ReceiptGenerator;

    const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

    #[tokio::test]
    async fn verifies_receipt_without_replay_state() {
        let provider = Arc::new(MockAttestationProvider::new());
        let generator = ReceiptGenerator::new(provider);
        let model_hash = [0x11; 32];
        let input_hash = [0x22; 32];
        let output_hash = [0x33; 32];
        let nonce = [0x44; 32];
        let receipt = generator
            .generate_receipt(model_hash, input_hash, output_hash, nonce)
            .await
            .unwrap();
        let request = VerifyRequest {
            receipt: Base64::encode_string(&receipt),
            model_hash: hex::encode(model_hash),
            input_hash: hex::encode(input_hash),
            output_hash: hex::encode(output_hash),
            nonce: hex::encode(nonce),
            expected_pcr0: hex::encode([0u8; 48]),
            trusted_root_pem: MOCK_ROOT_PEM.to_string(),
        };

        let first = verify(request.clone()).await.unwrap();
        let replay = verify(request).await.unwrap();
        assert!(first.valid);
        assert!(replay.valid, "WASM verification is intentionally stateless");
    }
}
