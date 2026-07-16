use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64ct::{Base64, Encoding};
use coset::{CborSerializable, CoseSign1};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use veriai_types::VeriClaims;
use veriai_types::openai::{ChatCompletionResponse, InferenceRequest, Message};

async fn receipt_nonce(response: axum::response::Response) -> [u8; 32] {
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let response: ChatCompletionResponse = serde_json::from_slice(&body).unwrap();
    let receipt = Base64::decode_vec(response.receipt.as_deref().unwrap()).unwrap();
    let cose = CoseSign1::from_slice(&receipt).unwrap();
    VeriClaims::from_binary(cose.payload.as_deref().unwrap())
        .unwrap()
        .client_nonce
}

#[tokio::test]
async fn test_openai_chat_completions_linkage() {
    let app = chat_demo::app();

    // Send a chat completion request.
    let request_body = json!({
        "model": "veriai-llama",
        "messages": [
            {
                "role": "user",
                "content": "hello veriai runtime"
            }
        ],
        "temperature": 0.7
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Decode the OpenAI-compatible response.
    let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let chat_response: ChatCompletionResponse = serde_json::from_slice(&body_bytes)
        .expect("Failed to parse standard OpenAI completion response JSON");

    // The mock runtime returns one assistant choice.
    assert_eq!(chat_response.choices.len(), 1);
    let choice = &chat_response.choices[0];
    assert_eq!(choice.message.role, "assistant");
    assert_eq!(chat_response.model, "veriai-mock");
    assert_eq!(
        choice.message.content,
        "VeriAI response: hello veriai runtime"
    );

    // 4. Assert Verification Proof block is valid
    let proof = chat_response
        .verification
        .as_ref()
        .expect("Verification proof block is missing in completions response");
    assert!(proof.valid);
    assert_eq!(proof.error, None);
    assert_eq!(proof.attestation_provider, "mock-nitro");
    assert!(!proof.verified_hardware);

    // 5. Assert Receipt linkage: verify prompt and response hash matches receipt
    let expected_input = InferenceRequest {
        model: "veriai-llama".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: "hello veriai runtime".to_string(),
        }],
        temperature: Some(0.7),
    };
    let expected_input_hash: [u8; 32] =
        Sha256::digest(expected_input.canonical_bytes().unwrap()).into();
    let expected_output_hash: [u8; 32] = Sha256::digest(choice.message.content.as_bytes()).into();

    let receipt_info = proof
        .receipt
        .as_ref()
        .expect("Receipt details metadata is missing inside proof");

    assert_eq!(receipt_info.input_hash, hex::encode(expected_input_hash));
    assert_eq!(receipt_info.output_hash, hex::encode(expected_output_hash));
}

#[tokio::test]
async fn test_proxy_endpoint_accepts_client_nonce() {
    let app = chat_demo::app();
    let request_body = json!({
        "model": "veriai-llama",
        "messages": [{"role": "user", "content": "proxy request"}]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/proxy/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-veriai-nonce", "11".repeat(32))
                .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let chat_response: ChatCompletionResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(chat_response.verification.unwrap().valid);

    let receipt = Base64::decode_vec(chat_response.receipt.as_deref().unwrap()).unwrap();
    let cose = CoseSign1::from_slice(&receipt).unwrap();
    let claims = VeriClaims::from_binary(cose.payload.as_deref().unwrap()).unwrap();
    assert_eq!(claims.client_nonce, [0x11; 32]);
}

#[tokio::test]
async fn test_proxy_endpoint_rejects_invalid_nonce() {
    let app = chat_demo::app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/proxy/v1/chat/completions")
                .header("content-type", "application/json")
                .header("x-veriai-nonce", "not-hex")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "model": "veriai-llama",
                        "messages": [{"role": "user", "content": "proxy request"}]
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_unbound_openai_parameters() {
    let response = chat_demo::app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "model": "veriai-mock",
                        "messages": [{"role": "user", "content": "hello"}],
                        "top_p": 0.9
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn demo_fallback_nonces_are_unique() {
    let app = chat_demo::app();
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "model": "veriai-mock",
                    "messages": [{"role": "user", "content": "nonce test"}]
                }))
                .unwrap(),
            ))
            .unwrap()
    };
    let first = app.clone().oneshot(request()).await.unwrap();
    let second = app.oneshot(request()).await.unwrap();
    assert_ne!(receipt_nonce(first).await, receipt_nonce(second).await);
}
