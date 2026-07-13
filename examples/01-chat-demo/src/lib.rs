use axum::{Json, Router, routing::post};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_runtime::{InferenceRuntime, mock::MockRuntime};
use veriai_types::openai::{
    ChatCompletionRequest, ChatCompletionResponse, Choice, InferenceRequest, Message, Usage,
};

const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

pub fn app() -> Router {
    Router::new().route("/v1/chat/completions", post(chat_completions_handler))
}

async fn chat_completions_handler(
    Json(payload): Json<ChatCompletionRequest>,
) -> Json<ChatCompletionResponse> {
    println!(
        "Received chat completions request for model: {:?}",
        payload.model
    );

    // 1. Resolve runtime (using deterministic MockRuntime)
    let runtime = MockRuntime::new();

    // 2. Perform async inference
    let inference_req = InferenceRequest {
        messages: payload.messages.clone(),
        temperature: payload.temperature,
    };
    let inference_result = runtime
        .generate(inference_req)
        .await
        .expect("Inference execution failed");

    // 3. Compute canonical inputs & outputs hashes (decoupled from runtime)
    // Prompt = last user message's content
    let prompt_content = payload
        .messages
        .last()
        .map(|m| m.content.as_str())
        .unwrap_or("hello");
    let input_hash: [u8; 32] = Sha256::digest(prompt_content.as_bytes()).into();
    let output_hash: [u8; 32] = Sha256::digest(inference_result.content.as_bytes()).into();

    // Model hash & Client nonce
    let model_hash = [0x55; 32];
    let client_nonce = [0x99; 32];

    // 4. Orchestration layer: Generate VeriAI Receipt
    let provider = Arc::new(MockAttestationProvider::new());
    let generator = ReceiptGenerator::new(provider.clone());

    let receipt_bytes = generator
        .generate_receipt(model_hash, input_hash, output_hash, client_nonce)
        .await
        .expect("Failed to generate enclave receipt");

    // 5. Orchestration layer: Verify Receipt
    let verifier = Verifier::from_pem(provider.clone(), MOCK_ROOT_PEM, false)
        .expect("Failed to initialize verifier");

    let expected_pcr0 = vec![0u8; 48]; // Mock provider uses zeroes for PCR0
    let verify_result = verifier
        .verify(
            &receipt_bytes,
            model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &expected_pcr0,
        )
        .await
        .expect("Verification processing failed");

    let created_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 6. Return OpenAI-compliant completions response decorated with verification proofs
    Json(ChatCompletionResponse {
        id: "chatcmpl-veriai-001".to_string(),
        object: "chat.completion".to_string(),
        created: created_time,
        model: payload.model,
        choices: vec![Choice {
            index: 0,
            message: Message {
                role: "assistant".to_string(),
                content: inference_result.content,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: Usage {
            prompt_tokens: (prompt_content.len() / 4) as u32,
            completion_tokens: inference_result.tokens_generated,
            total_tokens: ((prompt_content.len() / 4) as u32) + inference_result.tokens_generated,
        },
        verification: Some(verify_result),
    })
}
