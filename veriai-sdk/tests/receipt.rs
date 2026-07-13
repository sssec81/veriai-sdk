use veriai_sdk::receipt::ReceiptGenerator;
use veriai_sdk::nsm::schema::{AttestationDoc, VeriClaims};
use coset::{CoseSign1, CborSerializable};
use ed25519_dalek::{VerifyingKey, Verifier};

#[test]
fn test_receipt_generation_and_signature() {
    let generator = ReceiptGenerator::new();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt_bytes = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).expect("Failed to generate receipt");

    // 1. Decode COSE_Sign1
    let cose_sign1 = CoseSign1::from_slice(&receipt_bytes)
        .expect("Failed to decode COSE receipt");

    // 2. Verify signature on the receipt using generator's public key
    let pubkey_bytes = generator.public_key_bytes();
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .expect("Failed to parse verifying key");

    let tbs = cose_sign1.tbs_data(&[]);
    let signature_bytes: [u8; 64] = cose_sign1.signature.clone().try_into()
        .expect("Signature is not 64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    verifying_key.verify(&tbs, &signature)
        .expect("Receipt signature verification failed");

    // 3. Extract and parse VeriClaims payload
    let payload = cose_sign1.payload.expect("Receipt has no payload");
    let claims = VeriClaims::from_binary(&payload)
        .expect("Failed to decode VeriClaims");

    assert_eq!(claims.model_hash, model_hash);
    assert_eq!(claims.input_hash, input_hash);
    assert_eq!(claims.output_hash, output_hash);
    assert_eq!(claims.client_nonce, client_nonce);
    assert_eq!(claims.sequence_num, 0); // first sequence number should be 0
    assert_eq!(claims.enclave_pubkey, pubkey_bytes);

    // 4. Validate the enclosed attestation report
    let attestation_cose = CoseSign1::from_slice(&claims.attestation_report)
        .expect("Failed to decode enclosed attestation report");
    
    let doc_payload = attestation_cose.payload.expect("Attestation report has no payload");
    let doc = AttestationDoc::from_binary(&doc_payload)
        .expect("Failed to decode AttestationDoc");

    assert_eq!(doc.module_id, "Mock-Hypervisor-Module");
    assert_eq!(doc.nonce, Some(client_nonce.to_vec()));
    assert_eq!(doc.public_key, Some(pubkey_bytes.to_vec()));

    // Verify REPORTDATA binding: SHA-512(0x01 || "VeriAI-KeyBind-v1" || Ed25519_PubKey_32bytes)
    let expected_report_data = generator.compute_report_data();
    assert_eq!(doc.user_data, Some(expected_report_data.to_vec()));
}
