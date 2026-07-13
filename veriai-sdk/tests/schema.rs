use veriai_sdk::nsm::schema::{AttestationDoc, VeriClaims};
use std::collections::BTreeMap;

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
        attestation_timestamp: 1718300000,
        sdk_version: "veriai-sdk/1.0.0".to_string(),
        enclave_pubkey: [0xee; 32],
    };

    let serialized = claims.to_binary().expect("Failed to serialize claims");
    let deserialized = VeriClaims::from_binary(&serialized).expect("Failed to deserialize claims");

    assert_eq!(claims, deserialized);
}

#[test]
fn test_attestation_doc_roundtrip() {
    let mut pcrs = BTreeMap::new();
    pcrs.insert(0, vec![0x11; 48]);
    pcrs.insert(3, vec![0x22; 48]);

    let doc = AttestationDoc {
        module_id: "test-module".to_string(),
        timestamp: 1718300000000,
        digest: "SHA384".to_string(),
        pcrs,
        certificate: vec![0xaa, 0xbb],
        cabundle: vec![vec![0xcc, 0xdd]],
        public_key: Some(vec![0xee, 0xff]),
        user_data: Some(vec![0x12, 0x34]),
        nonce: Some(vec![0x56, 0x78]),
    };

    let serialized = doc.to_binary().expect("Failed to serialize doc");
    let deserialized = AttestationDoc::from_binary(&serialized).expect("Failed to deserialize doc");

    assert_eq!(doc, deserialized);
}
