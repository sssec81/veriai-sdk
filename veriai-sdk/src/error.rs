use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    InvalidCoseSignature,
    InvalidAttestationDocument,
    AttestationDocTimestampMismatch,
    PcrMismatch,
    PubkeyBindingMismatch,
    ReportDataMismatch,
    TimestampSkewExceeded,
    ModelHashMismatch,
    InputHashMismatch,
    OutputHashMismatch,
    NonceMismatch,
    SequenceNumberOutOfOrder,
    EnclaveIdentityChanged,
    MalformedReceipt,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCoseSignature => write!(f, "Invalid COSE signature"),
            Self::InvalidAttestationDocument => write!(f, "Invalid attestation document signature or structure"),
            Self::AttestationDocTimestampMismatch => write!(f, "Attestation document timestamp mismatch with payload timestamp"),
            Self::PcrMismatch => write!(f, "PCR0 value does not match expected value"),
            Self::PubkeyBindingMismatch => write!(f, "Enclave ephemeral public key does not match claim 6012"),
            Self::ReportDataMismatch => write!(f, "REPORTDATA (user_data) does not match SHA-512 binding hash of public key"),
            Self::TimestampSkewExceeded => write!(f, "Timestamp skew exceeds 5-minute skew tolerance"),
            Self::ModelHashMismatch => write!(f, "Model hash does not match expected value"),
            Self::InputHashMismatch => write!(f, "Input hash does not match expected value"),
            Self::OutputHashMismatch => write!(f, "Output hash does not match expected value"),
            Self::NonceMismatch => write!(f, "Client nonce does not match Nitro document nonce"),
            Self::SequenceNumberOutOfOrder => write!(f, "Sequence number is out of order (not monotonic)"),
            Self::EnclaveIdentityChanged => write!(f, "Enclave identity fingerprint changed on stateful verifier"),
            Self::MalformedReceipt => write!(f, "Malformed receipt structure"),
        }
    }
}

impl std::error::Error for VerifyError {}
