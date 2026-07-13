use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationError {
    #[error("NSM driver hardware unavailable: {0}")]
    HardwareUnavailable(String),

    #[error("Invalid attestation report signature or structure: {0}")]
    InvalidAttestationDocument(String),

    #[error("Attestation document validation failed: {0}")]
    ValidationError(String),
}

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerifyError {
    #[error("Invalid COSE signature")]
    InvalidCoseSignature,

    #[error("Invalid attestation document: {0}")]
    InvalidAttestationDocument(String),

    #[error("Attestation document timestamp mismatch with payload timestamp")]
    AttestationDocTimestampMismatch,

    #[error("PCR0 value does not match expected value")]
    PcrMismatch,

    #[error("Enclave ephemeral public key does not match claim 6012")]
    PubkeyBindingMismatch,

    #[error("REPORTDATA (user_data) does not match SHA-512 binding hash of public key")]
    ReportDataMismatch,

    #[error("Timestamp skew exceeds 5-minute skew tolerance")]
    TimestampSkewExceeded,

    #[error("Model hash does not match expected value")]
    ModelHashMismatch,

    #[error("Input hash does not match expected value")]
    InputHashMismatch,

    #[error("Output hash does not match expected value")]
    OutputHashMismatch,

    #[error("Client nonce does not match Nitro document nonce")]
    NonceMismatch,

    #[error("Sequence number is out of order (not monotonic)")]
    SequenceNumberOutOfOrder,

    #[error("Enclave identity fingerprint changed on stateful verifier")]
    EnclaveIdentityChanged,

    #[error("Malformed receipt structure")]
    MalformedReceipt,

    #[error("Attestation error: {0}")]
    Attestation(String),
}
