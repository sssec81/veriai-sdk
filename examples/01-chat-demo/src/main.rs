use axum::{
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use sha2::{Digest, Sha256};
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_types::VerificationCheck;

const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

#[derive(Deserialize, Debug)]
struct ChatRequest {
    prompt: String,
}

#[derive(Serialize, Debug)]
struct ProofDetails {
    verified: bool,
    model: String,
    hardware: String,
    checks: Vec<VerificationCheck>,
}

#[derive(Serialize, Debug)]
struct ChatResponse {
    answer: String,
    receipt: String,
    proof: ProofDetails,
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/chat", post(chat_handler));
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("VeriAI Chat Demo Server running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn chat_handler(Json(payload): Json<ChatRequest>) -> Json<ChatResponse> {
    println!("Received prompt: {:?}", payload.prompt);

    // 1. Run the mock model inference
    let answer = format!("VeriAI Secure Execution Output for prompt: '{}'", payload.prompt);

    // 2. Compute canonical inputs & outputs hashes
    let input_hash: [u8; 32] = Sha256::digest(payload.prompt.as_bytes()).into();
    let output_hash: [u8; 32] = Sha256::digest(answer.as_bytes()).into();

    // 3. Set dummy model Merkle root (representing llama-3-8b)
    let model_hash = [0x55; 32];
    let client_nonce = [0x99; 32];

    // 4. Generate the signed receipt inside the simulated Enclave
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());
    
    let receipt_bytes = generator.generate_receipt(
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
    ).await.expect("Failed to generate enclave receipt");

    // 5. Verify the receipt locally (simulating client-side or gateway validation)
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false)
        .expect("Failed to initialize verifier");

    let expected_pcr0 = vec![0u8; 48]; // Mock provider uses zeroes for PCR0
    let verify_result = verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        client_nonce,
        &expected_pcr0,
    ).await.expect("Verification processing failed");

    // 6. Return response decorated with verified checkmarks
    Json(ChatResponse {
        answer,
        receipt: hex::encode(&receipt_bytes),
        proof: ProofDetails {
            verified: verify_result.valid,
            model: "llama-3-8b-mock".to_string(),
            hardware: "AWS Nitro Enclave (Mocked)".to_string(),
            checks: verify_result.checks,
        },
    })
}
