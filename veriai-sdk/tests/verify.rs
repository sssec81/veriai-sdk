use veriai_sdk::receipt::ReceiptGenerator;
use veriai_sdk::verify::Verifier;
use veriai_sdk::error::VerifyError;

const MOCK_ROOT_PEM: &str = include_str!("fixtures/mock-aws-root.pem");

#[test]
fn test_verifier_end_to_end() {
    // 1. Create a stateful verifier initialized with our mock root certificate
    let verifier = Verifier::from_pem(MOCK_ROOT_PEM, true).expect("Failed to initialize verifier");

    // 2. Create generator and generate mock hashes
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

    // 3. Verify the receipt
    let pcr0 = vec![0u8; 48]; // mock.rs sets PCR0 to all zeroes
    verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    ).expect("Verification failed");

    // 4. Stateful Check: Verifying the same receipt again should fail with SequenceNumberOutOfOrder
    let verify_again_res = verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    );
    assert_eq!(verify_again_res, Err(VerifyError::SequenceNumberOutOfOrder));

    // 5. Stateful Check: Generating and verifying a new receipt (sequence_num = 1) should succeed
    let second_receipt = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).expect("Failed to generate second receipt");

    verifier.verify(
        &second_receipt,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &pcr0,
    ).expect("Second receipt verification failed");
}

#[test]
fn test_verifier_payload_mismatch_errors() {
    let verifier = Verifier::from_pem(MOCK_ROOT_PEM, false).expect("Failed to initialize verifier");
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

    let pcr0 = vec![0u8; 48];

    // Mismatched model hash
    let res = verifier.verify(&receipt_bytes, [0x00; 32], input_hash, output_hash, client_nonce, &pcr0);
    assert_eq!(res, Err(VerifyError::ModelHashMismatch));

    // Mismatched input hash
    let res = verifier.verify(&receipt_bytes, model_hash, [0x00; 32], output_hash, client_nonce, &pcr0);
    assert_eq!(res, Err(VerifyError::InputHashMismatch));

    // Mismatched output hash
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, [0x00; 32], client_nonce, &pcr0);
    assert_eq!(res, Err(VerifyError::OutputHashMismatch));

    // Mismatched client nonce
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, output_hash, [0x00; 32], &pcr0);
    assert_eq!(res, Err(VerifyError::NonceMismatch));

    // Mismatched PCR0
    let bad_pcr0 = vec![0xff; 48];
    let res = verifier.verify(&receipt_bytes, model_hash, input_hash, output_hash, client_nonce, &bad_pcr0);
    assert_eq!(res, Err(VerifyError::PcrMismatch));
}
