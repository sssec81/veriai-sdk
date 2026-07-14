pub mod mock;

#[cfg(all(feature = "mock-hardware", not(any(test, debug_assertions))))]
compile_error!("Production release builds cannot be compiled with mock-hardware enabled.");

#[cfg(feature = "real-hardware")]
pub mod nitro;

use async_trait::async_trait;
use coset::{CborSerializable, CoseSign1};
use p384::ecdsa::{VerifyingKey, signature::Verifier};
use std::time::SystemTime;
use veriai_types::AttestationDoc;
use veriai_types::error::AttestationError;
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

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

/// Helper to validate certificate validity period and CA constraint.
fn validate_cert(
    cert: &Certificate,
    is_leaf: bool,
    now: SystemTime,
) -> Result<(), AttestationError> {
    let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
    let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

    if now < not_before || now > not_after {
        return Err(AttestationError::ValidationError(
            "Certificate is outside its validity period".to_string(),
        ));
    }

    if !is_leaf {
        let mut is_ca = false;
        const BASIC_CONSTRAINTS_OID: x509_cert::der::asn1::ObjectIdentifier =
            x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");

        if let Some(ref ext_list) = cert.tbs_certificate.extensions {
            for ext in ext_list {
                if ext.extn_id == BASIC_CONSTRAINTS_OID {
                    let bc_res =
                        x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes());
                    if let Ok(bc) = bc_res {
                        is_ca = bc.ca;
                    }
                }
            }
        }
        if !is_ca {
            return Err(AttestationError::ValidationError(
                "Non-leaf certificate lacks CA:true constraint".to_string(),
            ));
        }
    }

    Ok(())
}

/// Shared attestation document verification function.
/// Parses the COSE_Sign1 document, validates signatures, verifies the certificate chain,
/// and enforces X.509 validity periods and basic constraints.
pub fn verify_attestation_doc(
    doc_bytes: &[u8],
    expected_root: &[u8],
    now: SystemTime,
) -> Result<AttestationDoc, AttestationError> {
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

    // Validate leaf cert validity
    validate_cert(&leaf_cert, true, now)?;

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
            AttestationError::InvalidAttestationDocument(format!("Invalid signature bytes: {}", e))
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

    // According to AWS Nitro Enclaves Attestation Document specification:
    // "The certificate chain contains intermediate and root certificates ordered from issuer
    // of the document's certificate to the root certificate." (leaf-to-root ordering:
    // leaf is signed by cabundle[0], cabundle[i] is signed by cabundle[i+1]).
    for cert_der in &doc.cabundle {
        let parent_cert = Certificate::from_der(cert_der).map_err(|e| {
            AttestationError::InvalidAttestationDocument(format!("Invalid parent cert: {}", e))
        })?;

        // Validate parent cert (intermediate CA)
        validate_cert(&parent_cert, false, now)?;

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
            AttestationError::InvalidAttestationDocument(format!("Invalid signature DER: {}", e))
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

    if !verified {
        return Err(AttestationError::ValidationError(
            "Certificate chain does not lead to a trusted root".to_string(),
        ));
    }

    Ok(doc)
}
