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
        match crate::verify_attestation_doc(doc_bytes, expected_root, std::time::SystemTime::now())
        {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
