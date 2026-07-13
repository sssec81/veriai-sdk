use std::sync::Arc;
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;

const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

#[tokio::test]
async fn test_verifier_end_to_end() {
    let provider = Arc::new(MockAttestationProvider::new());
    
    // 1. Create a stateful verifier initialized with our mock root certificate
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, true)
        .expect("Failed to initialize verifier");

    // 2. Create generator and generate mock hashes
    let generator = ReceiptGenerator::new(provider.clone());
    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt_bytes = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).await.expect("Failed to generate receipt");

    // 3. Verify the receipt
    let pcr0 = vec![0u8; 48]; // mock sets PCR0 to all zeroes
    let res = verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    ).await.expect("Verification failed");

    assert!(res.valid);
    assert_eq!(res.error, None);

    // 4. Stateful Check: Verifying the same receipt again should fail with SequenceNumberOutOfOrder
    let verify_again_res = verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    ).await.expect("Should return Ok VerificationResult");
    
    assert!(!verify_again_res.valid);
    assert_eq!(verify_again_res.error, Some("Sequence number is out of order (not monotonic)".to_string()));

    // 5. Stateful Check: Generating and verifying a new receipt (sequence_num = 1) should succeed
    let second_receipt = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).await.expect("Failed to generate second receipt");

    let res2 = verifier.verify(
        &second_receipt,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    ).await.expect("Second receipt verification failed");
    assert!(res2.valid);
}

#[tokio::test]
async fn test_verifier_payload_mismatch_errors() {
    let provider = Arc::new(MockAttestationProvider::new());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false)
        .expect("Failed to initialize verifier");
    let generator = ReceiptGenerator::new(provider.clone());

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt_bytes = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).await.expect("Failed to generate receipt");

    let pcr0 = vec![0u8; 48];

    // Mismatched model hash
    let res = verifier.verify(&receipt_bytes, [0x00; 32], input_hash, output_hash, client_nonce, &pcr0).await.unwrap();
    assert!(!res.valid);
    assert_eq!(res.error, Some("Model hash does not match expected value".to_string()));

    // Mismatched input hash
    let res = verifier.verify(&receipt_bytes, model_hash, [0x00; 32], output_hash, client_nonce, &pcr0).await.unwrap();
    assert!(!res.valid);
    assert_eq!(res.error, Some("Input hash does not match expected value".to_string()));

    // Mismatched output hash
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, [0x00; 32], client_nonce, &pcr0).await.unwrap();
    assert!(!res.valid);
    assert_eq!(res.error, Some("Output hash does not match expected value".to_string()));

    // Mismatched client nonce
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, output_hash, [0x00; 32], &pcr0).await.unwrap();
    assert!(!res.valid);
    assert_eq!(res.error, Some("Client nonce does not match Nitro document nonce".to_string()));

    // Mismatched PCR0
    let bad_pcr0 = vec![0xff; 48];
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, output_hash, client_nonce, &bad_pcr0).await.unwrap();
    assert!(!res.valid);
    assert_eq!(res.error, Some("PCR0 value does not match expected value".to_string()));
}
