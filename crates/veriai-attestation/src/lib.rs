#[cfg(feature = "mock-hardware")]
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

/// SHA-256 fingerprints of AWS Nitro Enclaves roots approved by this release.
/// Root rotation requires a reviewed source change.
pub const AWS_NITRO_ROOT_FINGERPRINTS: [[u8; 32]; 1] = [[
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
]];

/// Validate that a PEM bundle is well formed and that every certificate is an
/// explicitly approved AWS Nitro root. A single approved certificate must not
/// smuggle additional trust anchors into the verifier.
pub fn validate_aws_nitro_root_pem(pem: &str) -> Result<(), String> {
    validate_root_pem_with_allowlist(pem, &AWS_NITRO_ROOT_FINGERPRINTS)
}

fn validate_root_pem_with_allowlist(pem: &str, allowlist: &[[u8; 32]]) -> Result<(), String> {
    use base64ct::Encoding;
    use sha2::{Digest, Sha256};
    let mut encoded = String::new();
    let mut in_cert = false;
    let mut count = 0usize;
    for line in pem.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match line {
            "-----BEGIN CERTIFICATE-----" if !in_cert => {
                in_cert = true;
                encoded.clear();
            }
            "-----END CERTIFICATE-----" if in_cert => {
                let der = base64ct::Base64::decode_vec(&encoded)
                    .map_err(|e| format!("invalid trusted root PEM: {e}"))?;
                let fingerprint: [u8; 32] = Sha256::digest(&der).into();
                if !allowlist.contains(&fingerprint) {
                    return Err(format!(
                        "trusted root fingerprint is not allowlisted: {}",
                        hex::encode(fingerprint)
                    ));
                }
                count += 1;
                in_cert = false;
            }
            line if in_cert && !line.starts_with("-----") => encoded.push_str(line),
            _ => return Err("malformed or unexpected data in trusted root PEM".to_string()),
        }
    }
    if in_cert || count == 0 {
        return Err("trusted root PEM contains no complete certificates".to_string());
    }
    Ok(())
}

#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Stable provider name included in verification results.
    fn name(&self) -> &'static str {
        "custom"
    }

    /// Whether successful verification represents real hardware attestation.
    fn is_hardware_backed(&self) -> bool {
        false
    }

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
    subordinate_ca_count: usize,
    now: SystemTime,
) -> Result<(), AttestationError> {
    let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
    let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

    if now < not_before || now > not_after {
        return Err(AttestationError::ValidationError(
            "Certificate is outside its validity period".to_string(),
        ));
    }

    const BASIC_CONSTRAINTS_OID: x509_cert::der::asn1::ObjectIdentifier =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.19");
    const KEY_USAGE_OID: x509_cert::der::asn1::ObjectIdentifier =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.15");
    let mut basic_constraints = None;
    let mut key_usage = None;
    if let Some(ref extensions) = cert.tbs_certificate.extensions {
        for extension in extensions {
            if extension.extn_id == BASIC_CONSTRAINTS_OID {
                basic_constraints = Some(
                    x509_cert::ext::pkix::BasicConstraints::from_der(
                        extension.extn_value.as_bytes(),
                    )
                    .map_err(|_| {
                        AttestationError::ValidationError(
                            "Invalid basicConstraints extension".to_string(),
                        )
                    })?,
                );
            } else if extension.extn_id == KEY_USAGE_OID {
                key_usage = Some(
                    x509_cert::ext::pkix::KeyUsage::from_der(extension.extn_value.as_bytes())
                        .map_err(|_| {
                            AttestationError::ValidationError(
                                "Invalid keyUsage extension".to_string(),
                            )
                        })?,
                );
            } else if extension.critical {
                return Err(AttestationError::ValidationError(
                    "Certificate has an unsupported critical extension".to_string(),
                ));
            }
        }
    }

    if is_leaf {
        if basic_constraints
            .as_ref()
            .is_some_and(|constraints| constraints.ca)
        {
            return Err(AttestationError::ValidationError(
                "Attestation leaf certificate must not be a CA".to_string(),
            ));
        }
        if key_usage
            .as_ref()
            .is_some_and(|usage| !usage.digital_signature())
        {
            return Err(AttestationError::ValidationError(
                "Attestation leaf keyUsage lacks digitalSignature".to_string(),
            ));
        }
    } else {
        let constraints = basic_constraints.ok_or_else(|| {
            AttestationError::ValidationError(
                "Non-leaf certificate lacks CA:true constraint".to_string(),
            )
        })?;
        if !constraints.ca {
            return Err(AttestationError::ValidationError(
                "Non-leaf certificate lacks CA:true constraint".to_string(),
            ));
        }
        if key_usage
            .as_ref()
            .is_some_and(|usage| !usage.key_cert_sign())
        {
            return Err(AttestationError::ValidationError(
                "CA certificate keyUsage lacks keyCertSign".to_string(),
            ));
        }
        if let Some(limit) = constraints.path_len_constraint
            && subordinate_ca_count > usize::from(limit)
        {
            return Err(AttestationError::ValidationError(
                "CA certificate pathLenConstraint exceeded".to_string(),
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

    match attestation_cose.protected.header.alg.as_ref() {
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES384)) => {}
        _ => {
            return Err(AttestationError::InvalidAttestationDocument(
                "Attestation COSE protected header must declare ES384".to_string(),
            ));
        }
    }
    if attestation_cose.unprotected.alg.is_some() {
        return Err(AttestationError::InvalidAttestationDocument(
            "Attestation COSE algorithm must not be in the unprotected header".to_string(),
        ));
    }
    if !attestation_cose.protected.header.crit.is_empty()
        || !attestation_cose.unprotected.is_empty()
    {
        return Err(AttestationError::InvalidAttestationDocument(
            "Attestation COSE has unsupported critical or unprotected headers".to_string(),
        ));
    }

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
    validate_cert(&leaf_cert, true, 0, now)?;

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

    // AWS documents cabundle in root-first order.  Path validation starts at
    // the leaf, so walk the bundle in reverse: INTERM_N .. INTERM_1, ROOT.
    for (subordinate_ca_count, cert_der) in doc.cabundle.iter().rev().enumerate() {
        let parent_cert = Certificate::from_der(cert_der).map_err(|e| {
            AttestationError::InvalidAttestationDocument(format!("Invalid parent cert: {}", e))
        })?;

        // Validate parent cert (intermediate CA)
        validate_cert(&parent_cert, false, subordinate_ca_count, now)?;
        if current_cert.tbs_certificate.issuer != parent_cert.tbs_certificate.subject {
            return Err(AttestationError::ValidationError(
                "Certificate issuer does not match parent subject".to_string(),
            ));
        }

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

#[cfg(test)]
mod root_pin_tests {
    use super::validate_root_pem_with_allowlist;
    use base64ct::Encoding;
    use sha2::{Digest, Sha256};

    const ROOT: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");
    const INTERMEDIATE: &str = include_str!("../../../tests/fixtures/mock-aws-intermediate.pem");

    fn fingerprint(pem: &str) -> [u8; 32] {
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        Sha256::digest(base64ct::Base64::decode_vec(&body).unwrap()).into()
    }

    #[test]
    fn mixed_root_bundle_cannot_smuggle_an_unapproved_root() {
        let bundle = format!("{ROOT}\n{INTERMEDIATE}");
        assert!(validate_root_pem_with_allowlist(&bundle, &[fingerprint(ROOT)]).is_err());
    }
}
