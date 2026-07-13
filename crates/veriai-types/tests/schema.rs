use std::collections::BTreeMap;
use veriai_types::{AttestationDoc, VeriClaims};

#[test]
fn test_vericlaims_roundtrip() {
    let claims = VeriClaims {
        model_hash: [0xaa; 32],
        input_hash: [0xbb; 32],
        output_hash: [0xcc; 32],
        client_nonce: [0xdd; 32],
        sequence_num: 42,
        attestation_report: vec![1, 2, 3, 4],
        attestation_type: 3,
        attestation_timestamp: 1625097600,
        sdk_version: "veriai-sdk/1.0.0".to_string(),
        enclave_pubkey: [0xee; 32],
    };

    let serialized = claims.to_binary().expect("Failed to serialize VeriClaims");
    let deserialized =
        VeriClaims::from_binary(&serialized).expect("Failed to deserialize VeriClaims");

    assert_eq!(claims, deserialized);
}

#[test]
fn test_attestation_doc_roundtrip() {
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x11; 48]);
    pcrs.insert(1, vec![0x22; 48]);

    let doc = AttestationDoc {
        module_id: "test_module".to_string(),
        timestamp: 1625097600000,
        digest: "SHA384".to_string(),
        pcrs,
        certificate: vec![5, 6, 7],
        cabundle: vec![vec![8, 9], vec![10, 11]],
        public_key: Some(vec![12, 13]),
        user_data: Some(vec![14, 15]),
        nonce: Some(vec![16, 17]),
    };

    let serialized = doc.to_binary().expect("Failed to serialize AttestationDoc");
    let deserialized =
        AttestationDoc::from_binary(&serialized).expect("Failed to deserialize AttestationDoc");

    assert_eq!(doc, deserialized);
}
