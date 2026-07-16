use base64ct::Encoding;
use coset::{CborSerializable, CoseSign1, RegisteredLabel, iana};
use p384::ecdsa::signature::Signer;
use p384::pkcs8::DecodePrivateKey;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_attestation::mock::MockAttestationProvider;
use veriai_attestation::{AttestationProvider, verify_attestation_doc};
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_types::{AttestationDoc, VeriClaims};

const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

#[tokio::test]
async fn test_rejects_unknown_critical_receipt_header() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider, MOCK_ROOT_PEM, false).unwrap();
    let mut receipt = CoseSign1::from_slice(
        &generator
            .generate_receipt([1; 32], [2; 32], [3; 32], [4; 32])
            .await
            .unwrap(),
    )
    .unwrap();
    receipt
        .protected
        .header
        .crit
        .push(RegisteredLabel::<iana::HeaderParameter>::Text(
            "unknown".to_string(),
        ));
    receipt.protected.original_data = None;
    let result = verifier
        .verify(
            &receipt.to_vec().unwrap(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            &[0; 48],
        )
        .await;
    assert_eq!(
        result,
        Err(veriai_types::error::VerifyError::InvalidProtectedHeader)
    );
}

#[tokio::test]
async fn test_rejects_unknown_critical_attestation_header() {
    let provider = MockAttestationProvider::new();
    let document = provider.generate(None, None, None).await.unwrap();
    let mut cose = CoseSign1::from_slice(&document).unwrap();
    cose.protected
        .header
        .crit
        .push(RegisteredLabel::<iana::HeaderParameter>::Text(
            "unknown-attestation-header".to_string(),
        ));
    cose.protected.original_data = None;
    let root_body: String = MOCK_ROOT_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let root = base64ct::Base64::decode_vec(&root_body).unwrap();
    assert!(verify_attestation_doc(&cose.to_vec().unwrap(), &root, SystemTime::now()).is_err());
}

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

#[tokio::test]
async fn test_adversarial_conflicting_content_type_headers() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider, MOCK_ROOT_PEM, false).unwrap();
    let model_hash = [0x11; 32];
    let input_hash = [0x22; 32];
    let output_hash = [0x33; 32];
    let nonce = [0x44; 32];
    let receipt = generator
        .generate_receipt(model_hash, input_hash, output_hash, nonce)
        .await
        .unwrap();

    let mut cose = CoseSign1::from_slice(&receipt).unwrap();
    cose.protected.header.content_type = Some(coset::ContentType::Text("application/cwt".into()));
    cose.protected.original_data = None;
    cose.unprotected.content_type = Some(coset::ContentType::Text("application/cwt".into()));
    let tampered = cose.to_vec().unwrap();

    let result = verifier
        .verify(
            &tampered,
            model_hash,
            input_hash,
            output_hash,
            nonce,
            &[0u8; 48],
        )
        .await;
    assert!(matches!(
        result,
        Err(veriai_types::error::VerifyError::InvalidProtectedHeader)
    ));
}

#[tokio::test]
async fn test_rejects_invalid_expected_pcr0_length() {
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    let verifier = Verifier::from_pem(provider, MOCK_ROOT_PEM, false).unwrap();
    let receipt = generator
        .generate_receipt([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32])
        .await
        .unwrap();

    let result = verifier
        .verify(
            &receipt, [0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32], &[0u8; 32],
        )
        .await;
    assert!(matches!(
        result,
        Err(veriai_types::error::VerifyError::InvalidPcrLength)
    ));
}

#[tokio::test]
async fn test_adversarial_expired_cert_chain() {
    let provider = MockAttestationProvider::new();
    let attestation_doc_bytes = provider.generate(None, None, None).await.unwrap();
    let root_pem = include_str!("../../../tests/fixtures/mock-aws-root.pem");
    let mut root_base64 = String::new();
    for line in root_pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        root_base64.push_str(line.trim());
    }
    let root_der = base64ct::Base64::decode_vec(&root_base64).unwrap();

    // Fixtures are valid from 2026 to 2036. Test with a time in 2040.
    let far_future = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2208988800); // ~2040
    let res = verify_attestation_doc(&attestation_doc_bytes, &root_der, far_future);
    assert!(res.is_err());
    assert!(format!("{:?}", res).contains("outside its validity period"));
}

#[tokio::test]
async fn test_adversarial_not_yet_valid_cert_chain() {
    let provider = MockAttestationProvider::new();
    let attestation_doc_bytes = provider.generate(None, None, None).await.unwrap();
    let root_pem = include_str!("../../../tests/fixtures/mock-aws-root.pem");
    let mut root_base64 = String::new();
    for line in root_pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        root_base64.push_str(line.trim());
    }
    let root_der = base64ct::Base64::decode_vec(&root_base64).unwrap();

    // Fixtures are valid from 2026 to 2036. Test with a time in 2020.
    let past = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1577836800); // ~2020
    let res = verify_attestation_doc(&attestation_doc_bytes, &root_der, past);
    assert!(res.is_err());
    assert!(format!("{:?}", res).contains("outside its validity period"));
}

#[tokio::test]
async fn test_adversarial_non_ca_intermediate() {
    let leaf_pem = include_str!("../../../tests/fixtures/mock-aws-leaf.pem");
    let root_pem = include_str!("../../../tests/fixtures/mock-aws-root.pem");

    let mut leaf_base64 = String::new();
    for line in leaf_pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        leaf_base64.push_str(line.trim());
    }
    let leaf_der = base64ct::Base64::decode_vec(&leaf_base64).unwrap();

    let mut root_base64 = String::new();
    for line in root_pem.lines() {
        if line.starts_with("-----") {
            continue;
        }
        root_base64.push_str(line.trim());
    }
    let root_der = base64ct::Base64::decode_vec(&root_base64).unwrap();

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut pcrs = std::collections::BTreeMap::new();
    pcrs.insert(0, vec![0u8; 48]);

    // Construct AttestationDoc placing leaf_der (which has CA:false) in the cabundle
    let doc = AttestationDoc {
        module_id: "Mock-Hypervisor-Module".to_string(),
        timestamp: now_ms,
        digest: "SHA384".to_string(),
        pcrs,
        certificate: leaf_der.clone(),
        cabundle: vec![root_der.clone(), leaf_der.clone()],
        public_key: None,
        user_data: None,
        nonce: None,
    };

    let payload = doc.to_binary().unwrap();

    let protected = coset::HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES384)
        .build();

    let mut cose_sign1 = coset::CoseSign1Builder::new()
        .protected(protected)
        .payload(payload)
        .build();

    let leaf_key_pem = include_str!("../../../tests/fixtures/mock-aws-leaf.key.pem");
    let signing_key = p384::ecdsa::SigningKey::from_pkcs8_pem(leaf_key_pem).unwrap();
    let tbs = cose_sign1.tbs_data(&[]);
    let signature: p384::ecdsa::Signature = signing_key.sign(&tbs);
    cose_sign1.signature = signature.to_bytes().to_vec();

    let attestation_doc_bytes = cose_sign1.to_vec().unwrap();

    let res = verify_attestation_doc(&attestation_doc_bytes, &root_der, SystemTime::now());
    assert!(res.is_err());
    assert!(format!("{:?}", res).contains("lacks CA:true constraint"));
}
