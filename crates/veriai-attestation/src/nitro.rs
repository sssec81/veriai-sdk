use crate::AttestationProvider;
use async_trait::async_trait;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{VerifyingKey, signature::Verifier};
use veriai_types::AttestationDoc;
use veriai_types::error::AttestationError;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

pub struct NitroAttestationProvider;

impl NitroAttestationProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AttestationProvider for NitroAttestationProvider {
    async fn generate(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, AttestationError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(AttestationError::HardwareUnavailable(
                "Failed to open /dev/nsm driver".to_string(),
            ));
        }

        let request = Request::Attestation {
            nonce: nonce.map(|n| serde_bytes::ByteBuf::from(n.to_vec())),
            public_key: public_key.map(|k| serde_bytes::ByteBuf::from(k.to_vec())),
            user_data: user_data.map(|d| serde_bytes::ByteBuf::from(d.to_vec())),
        };

        let response = nsm_process_request(fd, request);
        nsm_exit(fd);

        match response {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => Err(AttestationError::ValidationError(format!(
                "NSM process request failed: {:?}",
                err
            ))),
            _ => Err(AttestationError::ValidationError(
                "Unexpected response type from NSM".to_string(),
            )),
        }
    }

    async fn verify(
        &self,
        doc_bytes: &[u8],
        expected_root: &[u8],
    ) -> Result<bool, AttestationError> {
        // Same cryptographic signature and chain checking as MockAttestationProvider, but checking against real expected root
        let attestation_cose = CoseSign1::from_slice(doc_bytes)
            .map_err(|e| AttestationError::InvalidAttestationDocument(e.to_string()))?;

        let attestation_payload = attestation_cose.payload.as_ref().ok_or_else(|| {
            AttestationError::InvalidAttestationDocument("Missing payload".to_string())
        })?;

        let doc = AttestationDoc::from_binary(attestation_payload)
            .map_err(|e| AttestationError::InvalidAttestationDocument(e.to_string()))?;

        // Verify attestation signature
        let leaf_cert = Certificate::from_der(&doc.certificate).map_err(|e| {
            AttestationError::InvalidAttestationDocument(format!(
                "Failed to parse leaf certificate: {}",
                e
            ))
        })?;

        let raw_leaf_pubkey = leaf_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let leaf_verifying_key = VerifyingKey::from_sec1_bytes(raw_leaf_pubkey).map_err(|e| {
            AttestationError::InvalidAttestationDocument(format!("Invalid public key: {}", e))
        })?;

        let attestation_signature = p384::ecdsa::Signature::from_slice(&attestation_cose.signature)
            .map_err(|e| {
                AttestationError::InvalidAttestationDocument(format!(
                    "Invalid signature bytes: {}",
                    e
                ))
            })?;

        let attestation_tbs = attestation_cose.tbs_data(&[]);
        leaf_verifying_key
            .verify(&attestation_tbs, &attestation_signature)
            .map_err(|e| {
                AttestationError::InvalidAttestationDocument(format!(
                    "Signature validation failed: {}",
                    e
                ))
            })?;

        // Verify Certificate Chain
        let mut current_cert = leaf_cert;
        let mut verified = false;

        for cert_der in &doc.cabundle {
            let parent_cert = Certificate::from_der(cert_der).map_err(|e| {
                AttestationError::InvalidAttestationDocument(format!("Invalid parent cert: {}", e))
            })?;

            let parent_pubkey_raw = parent_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes();
            let parent_verifying_key =
                VerifyingKey::from_sec1_bytes(parent_pubkey_raw).map_err(|e| {
                    AttestationError::InvalidAttestationDocument(format!(
                        "Invalid parent public key: {}",
                        e
                    ))
                })?;

            let current_tbs = current_cert.tbs_certificate.to_der().map_err(|e| {
                AttestationError::InvalidAttestationDocument(format!("Failed to encode TBS: {}", e))
            })?;

            let current_sig_bytes = current_cert.signature.raw_bytes();
            let current_sig = p384::ecdsa::Signature::from_der(current_sig_bytes).map_err(|e| {
                AttestationError::InvalidAttestationDocument(format!(
                    "Invalid signature DER: {}",
                    e
                ))
            })?;

            parent_verifying_key
                .verify(&current_tbs, &current_sig)
                .map_err(|e| {
                    AttestationError::InvalidAttestationDocument(format!(
                        "Chain signature validation failed: {}",
                        e
                    ))
                })?;

            let parent_der = parent_cert
                .to_der()
                .map_err(|e| AttestationError::InvalidAttestationDocument(e.to_string()))?;

            if parent_der == expected_root {
                verified = true;
                break;
            }

            current_cert = parent_cert;
        }

        if !verified {
            let current_der = current_cert
                .to_der()
                .map_err(|e| AttestationError::InvalidAttestationDocument(e.to_string()))?;
            if current_der == expected_root {
                verified = true;
            }
        }

        Ok(verified)
    }
}
