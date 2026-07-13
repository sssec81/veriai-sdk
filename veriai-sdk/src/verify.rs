use crate::error::VerifyError;
use crate::nsm::schema::{AttestationDoc, VeriClaims};
use base64ct::Encoding;
use coset::{CoseSign1, CborSerializable};
use ed25519_dalek::{VerifyingKey, Verifier as EdVerifier};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

/// Stateful Receipt Verifier
pub struct Verifier {
    trusted_roots: Vec<Vec<u8>>, // DER-encoded root certificates
    state: Option<Mutex<HashMap<[u8; 32], u64>>>, // Maps identity fingerprint to last sequence number
}

impl Verifier {
    /// Create a new Verifier with a list of trusted root certificates (DER bytes)
    pub fn new(trusted_roots: Vec<Vec<u8>>, stateful: bool) -> Self {
        Self {
            trusted_roots,
            state: if stateful { Some(Mutex::new(HashMap::new())) } else { None },
        }
    }

    /// Load trusted roots from a PEM string containing one or more certificates
    pub fn from_pem(pem_str: &str, stateful: bool) -> Result<Self, String> {
        let mut trusted_roots = Vec::new();
        let mut base64_str = String::new();
        let mut in_cert = false;

        for line in pem_str.lines() {
            let line = line.trim();
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                base64_str.clear();
            } else if line == "-----END CERTIFICATE-----" {
                if in_cert {
                    let der = base64ct::Base64::decode_vec(&base64_str)
                        .map_err(|e| format!("Failed to decode base64 certificate: {}", e))?;
                    trusted_roots.push(der);
                    in_cert = false;
                }
            } else if in_cert {
                base64_str.push_str(line);
            }
        }

        if trusted_roots.is_empty() {
            return Err("No certificates found in PEM".to_string());
        }

        Ok(Self::new(trusted_roots, stateful))
    }

    /// Validates a VeriAI receipt against the expectations.
    pub fn verify(
        &self,
        receipt_bytes: &[u8],
        expected_model_hash: [u8; 32],
        expected_input_hash: [u8; 32],
        expected_output_hash: [u8; 32],
        expected_nonce: [u8; 32],
        expected_pcr0: &[u8],
    ) -> Result<(), VerifyError> {
        // Step 1: Decode COSE_Sign1 Receipt and Verify signature using enclave pubkey (6012)
        let cose_receipt = CoseSign1::from_slice(receipt_bytes)
            .map_err(|_| VerifyError::MalformedReceipt)?;

        let payload = cose_receipt.payload.as_ref()
            .ok_or(VerifyError::MalformedReceipt)?;

        let claims = VeriClaims::from_binary(payload)
            .map_err(|_| VerifyError::MalformedReceipt)?;

        let receipt_verifying_key = VerifyingKey::from_bytes(&claims.enclave_pubkey)
            .map_err(|_| VerifyError::InvalidCoseSignature)?;

        let receipt_tbs = cose_receipt.tbs_data(&[]);
        let receipt_signature: [u8; 64] = cose_receipt.signature.clone().try_into()
            .map_err(|_| VerifyError::InvalidCoseSignature)?;
        let receipt_sig = ed25519_dalek::Signature::from_bytes(&receipt_signature);

        receipt_verifying_key.verify(&receipt_tbs, &receipt_sig)
            .map_err(|_| VerifyError::InvalidCoseSignature)?;

        // Step 2: Attestation Report Signature & Chain Validation
        let attestation_cose = CoseSign1::from_slice(&claims.attestation_report)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        let attestation_payload = attestation_cose.payload.as_ref()
            .ok_or(VerifyError::InvalidAttestationDocument)?;

        let doc = AttestationDoc::from_binary(attestation_payload)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        // Verify attestation signature
        let leaf_cert = Certificate::from_der(&doc.certificate)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        let raw_leaf_pubkey = leaf_cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
        let leaf_verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(raw_leaf_pubkey)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        let attestation_signature = p384::ecdsa::Signature::from_slice(&attestation_cose.signature)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        let attestation_tbs = attestation_cose.tbs_data(&[]);
        leaf_verifying_key.verify(&attestation_tbs, &attestation_signature)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?;

        // Verify Certificate Chain
        let mut current_cert = leaf_cert;
        let mut verified = false;

        for cert_der in &doc.cabundle {
            // Check if current certificate is signed by this certificate
            let parent_cert = Certificate::from_der(cert_der)
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            let parent_pubkey_raw = parent_cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
            let parent_verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(parent_pubkey_raw)
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            let current_tbs = current_cert.tbs_certificate.to_der()
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            let current_sig_bytes = current_cert.signature.raw_bytes();
            let current_sig = p384::ecdsa::Signature::from_der(current_sig_bytes)
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            parent_verifying_key.verify(&current_tbs, &current_sig)
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            // Check if parent certificate is a trusted root
            let parent_der = parent_cert.to_der()
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;

            if self.trusted_roots.contains(&parent_der) {
                verified = true;
                break;
            }

            current_cert = parent_cert;
        }

        // Check self-signed root verification if not matched in loop
        if !verified {
            let current_der = current_cert.to_der()
                .map_err(|_| VerifyError::InvalidAttestationDocument)?;
            if self.trusted_roots.contains(&current_der) {
                verified = true;
            }
        }

        if !verified {
            return Err(VerifyError::InvalidAttestationDocument);
        }

        // Verify Attestation Document Timestamp Skew (±5 min)
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::InvalidAttestationDocument)?
            .as_secs() as i64;

        let doc_sec = (doc.timestamp / 1000) as i64;

        if (now_sec - doc_sec).abs() > 300 {
            return Err(VerifyError::TimestampSkewExceeded);
        }

        if (now_sec - claims.attestation_timestamp).abs() > 300 {
            return Err(VerifyError::TimestampSkewExceeded);
        }

        if (doc_sec - claims.attestation_timestamp).abs() > 5 {
            return Err(VerifyError::AttestationDocTimestampMismatch);
        }

        // Step 3: PCR0 Validation
        let doc_pcr0 = doc.pcrs.get(&0)
            .ok_or(VerifyError::PcrMismatch)?;
        if doc_pcr0 != expected_pcr0 {
            return Err(VerifyError::PcrMismatch);
        }

        // Step 4: Pubkey Binding
        let doc_pubkey = doc.public_key.as_ref()
            .ok_or(VerifyError::PubkeyBindingMismatch)?;
        if doc_pubkey != &claims.enclave_pubkey {
            return Err(VerifyError::PubkeyBindingMismatch);
        }

        // Step 5: REPORTDATA Binding
        let doc_user_data = doc.user_data.as_ref()
            .ok_or(VerifyError::ReportDataMismatch)?;
        
        let mut hasher = Sha512::new();
        hasher.update(&[0x01]);
        hasher.update(b"VeriAI-KeyBind-v1");
        hasher.update(&claims.enclave_pubkey);
        let expected_report_data: [u8; 64] = hasher.finalize().into();

        if doc_user_data != &expected_report_data {
            return Err(VerifyError::ReportDataMismatch);
        }

        // Step 6: Payload Checks
        if doc.nonce.as_deref() != Some(&expected_nonce) {
            return Err(VerifyError::NonceMismatch);
        }

        if claims.client_nonce != expected_nonce {
            return Err(VerifyError::NonceMismatch);
        }

        if claims.model_hash != expected_model_hash {
            return Err(VerifyError::ModelHashMismatch);
        }

        if claims.input_hash != expected_input_hash {
            return Err(VerifyError::InputHashMismatch);
        }

        if claims.output_hash != expected_output_hash {
            return Err(VerifyError::OutputHashMismatch);
        }

        // Stateful sequence checking
        if let Some(ref state_mutex) = self.state {
            let mut state = state_mutex.lock().unwrap();
            let identity_fingerprint = compute_identity_fingerprint(&doc);
            
            if let Some(&last_seq) = state.get(&identity_fingerprint) {
                if claims.sequence_num <= last_seq {
                    return Err(VerifyError::SequenceNumberOutOfOrder);
                }
            }
            state.insert(identity_fingerprint, claims.sequence_num);
        }

        Ok(())
    }
}

fn compute_identity_fingerprint(doc: &AttestationDoc) -> [u8; 32] {
    let mut cert_hasher = Sha256::new();
    cert_hasher.update(&doc.certificate);
    for cert in &doc.cabundle {
        cert_hasher.update(cert);
    }
    let cert_fingerprint: [u8; 32] = cert_hasher.finalize().into();

    let mut hasher = Sha256::new();
    hasher.update(doc.pcrs.get(&0).cloned().unwrap_or_default());
    hasher.update(doc.pcrs.get(&3).cloned().unwrap_or_default());
    hasher.update(doc.pcrs.get(&4).cloned().unwrap_or_default());
    hasher.update(doc.module_id.as_bytes());
    hasher.update(&cert_fingerprint);
    hasher.finalize().into()
}
