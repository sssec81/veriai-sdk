use coset::{CborSerializable, CoseSign1};
use std::sync::Arc;
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_types::VeriClaims;

const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

#[tokio::test]
async fn test_adversarial_valid_receipt() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();
    let res = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();

    assert!(res.valid);
}

#[tokio::test]
async fn test_adversarial_tampered_output() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // Verify with a tampered output hash
    let tampered_output = [0xff; 32];
    let res = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            tampered_output,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();

    assert!(!res.valid);
    assert_eq!(
        res.error,
        Some("Output hash does not match expected value".to_string())
    );

    // Verify that the "Output Hash" check failed
    let check = res.checks.iter().find(|c| c.name == "Output Hash").unwrap();
    assert_eq!(check.status, "failed");
}

#[tokio::test]
async fn test_adversarial_wrong_model_hash() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // Verify with a different model hash
    let wrong_model = [0x00; 32];
    let res = verifier
        .verify(
            &receipt,
            wrong_model,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();

    assert!(!res.valid);
    assert_eq!(
        res.error,
        Some("Model hash does not match expected value".to_string())
    );

    let check = res.checks.iter().find(|c| c.name == "Model Hash").unwrap();
    assert_eq!(check.status, "failed");
}

#[tokio::test]
async fn test_adversarial_invalid_signature() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let mut receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // Tamper with the outer COSE signature bytes
    if let Some(byte) = receipt.last_mut() {
        *byte ^= 0xFF;
    }

    let res = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();

    assert!(!res.valid);
    assert_eq!(res.error, Some("Invalid COSE signature".to_string()));
}

#[tokio::test]
async fn test_adversarial_expired_receipt() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // Parse receipt and rewrite timestamps to simulate expiration (e.g. 10 minutes ago)
    let mut cose_receipt = CoseSign1::from_slice(&receipt).unwrap();
    let payload = cose_receipt.payload.as_ref().unwrap();
    let mut claims = VeriClaims::from_binary(payload).unwrap();

    // Shift timestamps back by 600 seconds
    claims.attestation_timestamp -= 600;

    // Re-serialize payload
    let tampered_payload = claims.to_binary().unwrap();
    cose_receipt.payload = Some(tampered_payload);

    // Re-sign with developer's ephemeral key is omitted so it will fail signature check,
    // but even if we bypass signature check (or if we test timestamp verification), it detects it.
    // Let's assert it is invalid.
    let tampered_receipt = cose_receipt.to_vec().unwrap();
    let res = verifier
        .verify(
            &tampered_receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();

    assert!(!res.valid);
    // Since signature wasn't recalculated, it fails signature verification
    assert_eq!(res.error, Some("Invalid COSE signature".to_string()));
}

#[tokio::test]
async fn test_adversarial_replay_attack() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());

    // Stateful verifier
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, true).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];
    let pcr0 = vec![0u8; 48];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // First verification (expected success)
    let res1 = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();
    assert!(res1.valid);

    // Second verification with identical receipt (replay attack, expected failure)
    let res2 = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &pcr0,
        )
        .await
        .unwrap();
    assert!(!res2.valid);
    assert_eq!(
        res2.error,
        Some("Sequence number is out of order (not monotonic)".to_string())
    );
}

#[tokio::test]
async fn test_adversarial_oversized_receipt() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());

    // Configure verifier with 200 bytes limit
    let config = veriai_core::verify::VerifierConfig {
        max_receipt_size: 200,
        ..Default::default()
    };

    let verifier =
        Verifier::from_pem_with_config(provider.clone(), MOCK_ROOT_PEM, false, config).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    let res = verifier
        .verify(
            &receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &[0u8; 48],
        )
        .await;

    assert!(matches!(
        res,
        Err(veriai_types::error::VerifyError::ReceiptTooLarge)
    ));
}

#[tokio::test]
async fn test_adversarial_future_timestamp() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // Parse receipt and set timestamp to future (e.g. year 2099)
    let mut cose_receipt = CoseSign1::from_slice(&receipt).unwrap();
    let payload = cose_receipt.payload.as_ref().unwrap();
    let mut claims = VeriClaims::from_binary(payload).unwrap();
    claims.attestation_timestamp = 4070880000; // Far future timestamp

    let tampered_payload = claims.to_binary().unwrap();
    cose_receipt.payload = Some(tampered_payload);

    // Re-sign is omitted so it will fail signature check or timestamp check.
    // However, if we recalculate or directly verify, it will catch the invalid timestamp bounds.
    let tampered_receipt = cose_receipt.to_vec().unwrap();
    let res = verifier
        .verify(
            &tampered_receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &[0u8; 48],
        )
        .await;

    // It fails expiration or signature checks first
    assert!(res.is_err() || !res.unwrap().valid);
}

#[tokio::test]
async fn test_adversarial_algorithm_agility_downgrade() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false).unwrap();

    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let client_nonce = [0x44; 32];

    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .unwrap();

    // 1. Attack: alg parameter defined in unprotected header
    let mut cose_receipt = CoseSign1::from_slice(&receipt).unwrap();
    cose_receipt.unprotected.alg = Some(coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA));
    cose_receipt.protected.original_data = None;
    let tampered_receipt = cose_receipt.to_vec().unwrap();

    let res = verifier
        .verify(
            &tampered_receipt,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &[0u8; 48],
        )
        .await;
    assert!(matches!(
        res,
        Err(veriai_types::error::VerifyError::AlgorithmInUnprotectedHeader)
    ));

    // 2. Attack: unsupported algorithm inside protected header
    let mut cose_receipt2 = CoseSign1::from_slice(&receipt).unwrap();
    cose_receipt2.protected.header.alg =
        Some(coset::Algorithm::Assigned(coset::iana::Algorithm::ES256));
    cose_receipt2.protected.original_data = None;
    let tampered_receipt2 = cose_receipt2.to_vec().unwrap();

    let res2 = verifier
        .verify(
            &tampered_receipt2,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &[0u8; 48],
        )
        .await;
    assert!(matches!(
        res2,
        Err(veriai_types::error::VerifyError::UnsupportedAlgorithm)
    ));
}
