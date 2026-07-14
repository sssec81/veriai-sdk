use crate::AttestationProvider;
use async_trait::async_trait;
use base64ct::{Base64, Encoding};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, iana};
use p384::ecdsa::{SigningKey, signature::Signer};
use p384::pkcs8::DecodePrivateKey;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_types::AttestationDoc;
use veriai_types::error::AttestationError;

// Embed mock certificates and private signing keys at compile time
const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");
const MOCK_INTERMEDIATE_PEM: &str =
    include_str!("../../../tests/fixtures/mock-aws-intermediate.pem");
const MOCK_LEAF_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-leaf.pem");
const MOCK_LEAF_KEY_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-leaf.key.pem");

fn pem_to_der(pem: &str) -> Vec<u8> {
    let mut base64_str = String::new();
    for line in pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        base64_str.push_str(line.trim());
    }
    Base64::decode_vec(&base64_str).expect("Failed to decode base64 PEM")
}

pub struct MockAttestationProvider;

impl MockAttestationProvider {
    pub fn new() -> Self {
        Self
    }
}
impl Default for MockAttestationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationProvider for MockAttestationProvider {
    async fn generate(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::ValidationError(e.to_string()))?
            .as_millis() as u64;

        let leaf_der = pem_to_der(MOCK_LEAF_PEM);
        let intermediate_der = pem_to_der(MOCK_INTERMEDIATE_PEM);
        let root_der = pem_to_der(MOCK_ROOT_PEM);

        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, vec![0u8; 48]);
        pcrs.insert(3, vec![0u8; 48]);
        pcrs.insert(4, vec![0u8; 48]);

        let doc = AttestationDoc {
            module_id: "Mock-Hypervisor-Module".to_string(),
            timestamp: now_ms,
            digest: "SHA384".to_string(),
            pcrs,
            certificate: leaf_der,
            cabundle: vec![intermediate_der, root_der],
            public_key: public_key.map(|k| k.to_vec()),
            user_data: user_data.map(|d| d.to_vec()),
            nonce: nonce.map(|n| n.to_vec()),
        };

        let payload = doc
            .to_binary()
            .map_err(|e| AttestationError::ValidationError(e.to_string()))?;

        // Build the COSE_Sign1 structure
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build();

        let mut cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .build();

        // Sign the payload
        let signing_key = SigningKey::from_pkcs8_pem(MOCK_LEAF_KEY_PEM).map_err(|e| {
            AttestationError::ValidationError(format!("Failed to parse signing key: {}", e))
        })?;

        let tbs = cose_sign1.tbs_data(&[]);
        let signature: p384::ecdsa::Signature = signing_key.sign(&tbs);
        cose_sign1.signature = signature.to_bytes().to_vec();

        cose_sign1.to_vec().map_err(|e| {
            AttestationError::ValidationError(format!("Failed to serialize COSE_Sign1: {}", e))
        })
    }

    async fn verify(
        &self,
        doc_bytes: &[u8],
        expected_root: &[u8],
    ) -> Result<bool, AttestationError> {
        match crate::verify_attestation_doc(doc_bytes, expected_root, std::time::SystemTime::now()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
