use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request, nsm_exit};

/// Fetches the real attestation document from the Nitro Secure Module (/dev/nsm)
pub fn get_attestation_document(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let fd = nsm_init();
    if fd < 0 {
        return Err("Failed to initialize NSM driver".to_string());
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
        Response::Error(err) => Err(format!("NSM driver error: {:?}", err)),
        _ => Err("Unexpected response from NSM driver".to_string()),
    }
}
