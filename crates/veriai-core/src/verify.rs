use base64ct::Encoding;
use coset::{CborSerializable, CoseSign1};
use ed25519_dalek::{Verifier as EdVerifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_attestation::AttestationProvider;
use veriai_types::error::VerifyError;
use veriai_types::{
    AttestationDoc, ReceiptInfo, VeriClaims, VerificationCheck, VerificationResult,
};

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub max_receipt_size: usize,
    pub max_clock_skew: i64,
    pub max_receipt_age: i64,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_receipt_size: 64 * 1024,
            max_clock_skew: 300,
            max_receipt_age: 300,
        }
    }
}

/// Stateful Receipt Verifier
pub struct Verifier {
    provider: Arc<dyn AttestationProvider>,
    trusted_roots: Vec<Vec<u8>>, // DER-encoded root certificates
    state: Option<Mutex<HashMap<[u8; 32], u64>>>, // Maps identity fingerprint to last sequence number
    config: VerifierConfig,
}

impl Verifier {
    /// Create a new Verifier with default config options.
    ///
    /// # Security Note
    /// Callers are responsible for only ever populating `trusted_roots` with roots they actually trust.
    /// The verification loop checks certificates up to any of these roots, breaking on the first root that
    /// validates, with no additional filtering inside the verifier.
    pub fn new(
        provider: Arc<dyn AttestationProvider>,
        trusted_roots: Vec<Vec<u8>>,
        stateful: bool,
    ) -> Self {
        Self::new_with_config(provider, trusted_roots, stateful, VerifierConfig::default())
    }

    /// Create a new Verifier with custom config options.
    ///
    /// # Security Note
    /// Callers are responsible for only ever populating `trusted_roots` with roots they actually trust.
    /// The verification loop checks certificates up to any of these roots, breaking on the first root that
    /// validates, with no additional filtering inside the verifier.
    pub fn new_with_config(
        provider: Arc<dyn AttestationProvider>,
        trusted_roots: Vec<Vec<u8>>,
        stateful: bool,
        config: VerifierConfig,
    ) -> Self {
        Self {
            provider,
            trusted_roots,
            state: if stateful {
                Some(Mutex::new(HashMap::new()))
            } else {
                None
            },
            config,
        }
    }

    /// Load trusted roots from a PEM string containing one or more certificates
    pub fn from_pem(
        provider: Arc<dyn AttestationProvider>,
        pem_str: &str,
        stateful: bool,
    ) -> Result<Self, String> {
        Self::from_pem_with_config(provider, pem_str, stateful, VerifierConfig::default())
    }

    /// Load trusted roots from a PEM string with custom configuration
    pub fn from_pem_with_config(
        provider: Arc<dyn AttestationProvider>,
        pem_str: &str,
        stateful: bool,
        config: VerifierConfig,
    ) -> Result<Self, String> {
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

        Ok(Self::new_with_config(
            provider,
            trusted_roots,
            stateful,
            config,
        ))
    }

    /// Validates a VeriAI receipt and returns a detailed VerificationResult
    pub async fn verify(
        &self,
        receipt_bytes: &[u8],
        expected_model_hash: [u8; 32],
        expected_input_hash: [u8; 32],
        expected_output_hash: [u8; 32],
        expected_nonce: [u8; 32],
        expected_pcr0: &[u8],
    ) -> Result<VerificationResult, VerifyError> {
        let mut checks = Vec::new();
        let mut receipt_info = None;

        // Helper macro to add check results
        macro_rules! add_check {
            ($name:expr, $status:expr, $details:expr) => {
                checks.push(VerificationCheck {
                    name: $name.to_string(),
                    status: $status.to_string(),
                    details: $details,
                });
            };
        }

        // Helper to generate failure results using a macro to avoid borrowing receipt_info
        macro_rules! fail_result {
            ($err:expr, $checks_list:expr) => {
                VerificationResult {
                    valid: false,
                    receipt: receipt_info.clone(),
                    checks: $checks_list,
                    attestation_provider: "nitro".to_string(),
                    verified_hardware: false,
                    error: Some($err.to_string()),
                }
            };
        }

        // Check 0: Pre-allocation Receipt Size limit check
        if receipt_bytes.len() > self.config.max_receipt_size {
            return Err(VerifyError::ReceiptTooLarge);
        }

        // Check 1: Parse Receipt Structure
        let cose_receipt = match CoseSign1::from_slice(receipt_bytes) {
            Ok(c) => {
                // Check 0B: Algorithm Agility and Downgrade checks
                // 1. Verify protected header specifies EdDSA (-8)
                let protected_alg = c
                    .protected
                    .header
                    .alg
                    .as_ref()
                    .ok_or(VerifyError::InvalidProtectedHeader)?;
                match protected_alg {
                    coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA) => {}
                    _ => {
                        return Err(VerifyError::UnsupportedAlgorithm);
                    }
                }
                // 2. Reject any algorithm specified in the unprotected header
                if c.unprotected.alg.is_some() {
                    return Err(VerifyError::AlgorithmInUnprotectedHeader);
                }
                add_check!("Receipt Format", "passed", None);
                c
            }
            Err(e) => {
                add_check!("Receipt Format", "failed", Some(e.to_string()));
                return Ok(fail_result!(VerifyError::MalformedReceipt, checks));
            }
        };

        let payload = match cose_receipt.payload.as_ref() {
            Some(p) => p,
            None => {
                add_check!(
                    "Receipt Payload",
                    "failed",
                    Some("Missing payload".to_string())
                );
                return Ok(fail_result!(VerifyError::MalformedReceipt, checks));
            }
        };

        let claims = match VeriClaims::from_binary(payload) {
            Ok(c) => {
                receipt_info = Some(ReceiptInfo {
                    version: claims_version_str(c.sdk_version.as_str()),
                    model_hash: hex::encode(c.model_hash),
                    input_hash: hex::encode(c.input_hash),
                    output_hash: hex::encode(c.output_hash),
                    sequence_num: c.sequence_num,
                    timestamp: c.attestation_timestamp,
                });
                add_check!("Claims Parsing", "passed", None);
                c
            }
            Err(e) => {
                add_check!("Claims Parsing", "failed", Some(e.to_string()));
                return Ok(fail_result!(VerifyError::MalformedReceipt, checks));
            }
        };

        if claims.attestation_type != 3 {
            add_check!(
                "Attestation Type",
                "failed",
                Some(format!(
                    "Expected Nitro attestation type 3, got {}",
                    claims.attestation_type
                ))
            );
            return Ok(fail_result!(
                VerifyError::UnsupportedAttestationType,
                checks
            ));
        }
        add_check!("Attestation Type", "passed", None);

        // Check 2: Verify Receipt Signature (Ed25519)
        let receipt_sig_verified = match VerifyingKey::from_bytes(&claims.enclave_pubkey) {
            Ok(key) => {
                let receipt_tbs = cose_receipt.tbs_data(&[]);
                if let Ok(sig_bytes) = cose_receipt.signature.clone().try_into() {
                    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                    key.verify(&receipt_tbs, &sig).is_ok()
                } else {
                    false
                }
            }
            Err(_) => false,
        };

        if receipt_sig_verified {
            add_check!("Receipt Signature", "passed", None);
        } else {
            add_check!(
                "Receipt Signature",
                "failed",
                Some("Ed25519 validation failed".to_string())
            );
            return Ok(fail_result!(VerifyError::InvalidCoseSignature, checks));
        }

        // Check 3: Attestation Report Signature & Chain Validation
        let attestation_cose = match CoseSign1::from_slice(&claims.attestation_report) {
            Ok(c) => c,
            Err(e) => {
                add_check!("Attestation Format", "failed", Some(e.to_string()));
                return Ok(fail_result!(
                    VerifyError::InvalidAttestationDocument(e.to_string()),
                    checks
                ));
            }
        };

        let attestation_payload = match attestation_cose.payload.as_ref() {
            Some(p) => p,
            None => {
                add_check!(
                    "Attestation Payload",
                    "failed",
                    Some("Missing payload".to_string())
                );
                return Ok(fail_result!(
                    VerifyError::InvalidAttestationDocument("Missing payload".to_string()),
                    checks
                ));
            }
        };

        let doc = match AttestationDoc::from_binary(attestation_payload) {
            Ok(d) => d,
            Err(e) => {
                add_check!("Attestation Doc Parsing", "failed", Some(e.to_string()));
                return Ok(fail_result!(
                    VerifyError::InvalidAttestationDocument(e.to_string()),
                    checks
                ));
            }
        };

        // Signature and chain verification via the provider
        let mut verified_chain = false;
        for root in &self.trusted_roots {
            if let Ok(true) = self.provider.verify(&claims.attestation_report, root).await {
                verified_chain = true;
                break;
            }
        }

        if verified_chain {
            add_check!("Attestation Signature & Chain", "passed", None);
        } else {
            add_check!(
                "Attestation Signature & Chain",
                "failed",
                Some("Signature or chain verification failed".to_string())
            );
            return Ok(fail_result!(
                VerifyError::InvalidAttestationDocument("Verification failed".to_string()),
                checks
            ));
        }

        // Verify timestamps
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VerifyError::InvalidAttestationDocument("Clock error".to_string()))?
            .as_secs() as i64;

        let doc_sec = (doc.timestamp / 1000) as i64;

        // 1. Skew check for Attestation Document
        let skew = now_sec
            .checked_sub(doc_sec)
            .ok_or(VerifyError::InvalidTimestamp)?;
        if skew.abs() > self.config.max_clock_skew {
            add_check!(
                "Attestation Timestamp Skew",
                "failed",
                Some(format!("Skew is {}s", skew.abs()))
            );
            return Ok(fail_result!(VerifyError::TimestampSkewExceeded, checks));
        } else {
            add_check!("Attestation Timestamp Skew", "passed", None);
        }

        // 2. Age check for Receipt (SEC-02B)
        let receipt_age = now_sec
            .checked_sub(claims.attestation_timestamp)
            .ok_or(VerifyError::InvalidTimestamp)?;
        if receipt_age < 0 || receipt_age > self.config.max_receipt_age {
            add_check!(
                "Receipt Timestamp Skew",
                "failed",
                Some(format!("Age is {}s", receipt_age))
            );
            return Err(VerifyError::ExpiredReceipt);
        } else {
            add_check!("Receipt Timestamp Skew", "passed", None);
        }

        // 3. Alignment check between document and receipt
        let alignment = doc_sec
            .checked_sub(claims.attestation_timestamp)
            .ok_or(VerifyError::InvalidTimestamp)?;
        if alignment.abs() > 5 {
            add_check!(
                "Timestamp Alignment",
                "failed",
                Some(format!(
                    "Mismatch between doc and claims is {}s",
                    alignment.abs()
                ))
            );
            return Ok(fail_result!(
                VerifyError::AttestationDocTimestampMismatch,
                checks
            ));
        } else {
            add_check!("Timestamp Alignment", "passed", None);
        }

        // Check 4: PCR0 Validation
        let doc_pcr0 = match doc.pcrs.get(&0) {
            Some(p) => p,
            None => {
                add_check!(
                    "PCR0 Check",
                    "failed",
                    Some("PCR0 missing in document".to_string())
                );
                return Ok(fail_result!(VerifyError::PcrMismatch, checks));
            }
        };

        if doc_pcr0 == expected_pcr0 {
            add_check!("PCR0 Check", "passed", None);
        } else {
            add_check!(
                "PCR0 Check",
                "failed",
                Some(format!(
                    "Expected: {}, Got: {}",
                    hex::encode(expected_pcr0),
                    hex::encode(doc_pcr0)
                ))
            );
            return Ok(fail_result!(VerifyError::PcrMismatch, checks));
        }

        // Check 5: Pubkey Binding
        let doc_pubkey = match doc.public_key.as_ref() {
            Some(k) => k,
            None => {
                add_check!(
                    "Pubkey Binding",
                    "failed",
                    Some("Public key missing in document".to_string())
                );
                return Ok(fail_result!(VerifyError::PubkeyBindingMismatch, checks));
            }
        };

        if doc_pubkey == &claims.enclave_pubkey {
            add_check!("Pubkey Binding", "passed", None);
        } else {
            add_check!(
                "Pubkey Binding",
                "failed",
                Some("Public key mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::PubkeyBindingMismatch, checks));
        }

        // Check 6: REPORTDATA Binding
        let doc_user_data = match doc.user_data.as_ref() {
            Some(d) => d,
            None => {
                add_check!(
                    "REPORTDATA Binding",
                    "failed",
                    Some("User data missing in document".to_string())
                );
                return Ok(fail_result!(VerifyError::ReportDataMismatch, checks));
            }
        };

        let mut hasher = Sha512::new();
        hasher.update([0x01]);
        hasher.update(b"VeriAI-KeyBind-v1");
        hasher.update(claims.enclave_pubkey);
        let expected_report_data: [u8; 64] = hasher.finalize().into();

        if doc_user_data == &expected_report_data {
            add_check!("REPORTDATA Binding", "passed", None);
        } else {
            add_check!(
                "REPORTDATA Binding",
                "failed",
                Some("REPORTDATA hash mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::ReportDataMismatch, checks));
        }

        // Check 7: Payload Integrity (Nonces & Hashes)
        if doc.nonce.as_deref() == Some(&expected_nonce) && claims.client_nonce == expected_nonce {
            add_check!("Nonce Matching", "passed", None);
        } else {
            add_check!(
                "Nonce Matching",
                "failed",
                Some("Nonce mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::NonceMismatch, checks));
        }

        if claims.model_hash == expected_model_hash {
            add_check!("Model Hash", "passed", None);
        } else {
            add_check!(
                "Model Hash",
                "failed",
                Some("Model Merkle root mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::ModelHashMismatch, checks));
        }

        if claims.input_hash == expected_input_hash {
            add_check!("Input Hash", "passed", None);
        } else {
            add_check!(
                "Input Hash",
                "failed",
                Some("Input hash mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::InputHashMismatch, checks));
        }

        if claims.output_hash == expected_output_hash {
            add_check!("Output Hash", "passed", None);
        } else {
            add_check!(
                "Output Hash",
                "failed",
                Some("Output hash mismatch".to_string())
            );
            return Ok(fail_result!(VerifyError::OutputHashMismatch, checks));
        }

        // Stateful sequence checks
        if let Some(ref state_mutex) = self.state {
            let mut state = state_mutex.lock().unwrap();
            let identity_fingerprint = compute_identity_fingerprint(&doc);

            if let Some(&last_seq) = state
                .get(&identity_fingerprint)
                .filter(|&&last| claims.sequence_num <= last)
            {
                add_check!(
                    "Sequence Check",
                    "failed",
                    Some(format!(
                        "Sequence {} is out of order (last was {})",
                        claims.sequence_num, last_seq
                    ))
                );
                return Ok(fail_result!(VerifyError::SequenceNumberOutOfOrder, checks));
            }
            state.insert(identity_fingerprint, claims.sequence_num);
            add_check!("Sequence Check", "passed", None);
        }

        Ok(VerificationResult {
            valid: true,
            receipt: receipt_info,
            checks,
            attestation_provider: "nitro".to_string(),
            verified_hardware: true,
            error: None,
        })
    }

    /// Returns a copy of the internal sequence validation state (if stateful)
    pub fn get_state(&self) -> Option<HashMap<[u8; 32], u64>> {
        self.state.as_ref().map(|s| s.lock().unwrap().clone())
    }

    /// Sets/restores the internal sequence validation state (if stateful)
    pub fn set_state(&self, new_state: HashMap<[u8; 32], u64>) {
        if let Some(ref s) = self.state {
            *s.lock().unwrap() = new_state;
        }
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
    hasher.update(cert_fingerprint);
    hasher.finalize().into()
}

fn claims_version_str(sdk_version: &str) -> String {
    if sdk_version.contains('/') {
        sdk_version
            .split('/')
            .next_back()
            .unwrap_or("1")
            .to_string()
    } else {
        "1".to_string()
    }
}
