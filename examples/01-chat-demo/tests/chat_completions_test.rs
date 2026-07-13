use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use veriai_types::openai::ChatCompletionResponse;

#[tokio::test]
async fn test_openai_chat_completions_linkage() {
    let app = chat_demo::app();

    // 1. Send chat completion request
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

    // 2. Decode standard OpenAI completions JSON response
    let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    let chat_response: ChatCompletionResponse = serde_json::from_slice(&body_bytes)
        .expect("Failed to parse standard OpenAI completion response JSON");

    // 3. Assert Choice & deterministic mock content
    assert_eq!(chat_response.choices.len(), 1);
    let choice = &chat_response.choices[0];
    assert_eq!(choice.message.role, "assistant");
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

    // 5. Assert Receipt linkage: verify prompt and response hash matches receipt
    let expected_input_hash: [u8; 32] = Sha256::digest(b"hello veriai runtime").into();
    let expected_output_hash: [u8; 32] = Sha256::digest(choice.message.content.as_bytes()).into();

    let receipt_info = proof
        .receipt
        .as_ref()
        .expect("Receipt details metadata is missing inside proof");

    assert_eq!(receipt_info.input_hash, hex::encode(expected_input_hash));
    assert_eq!(receipt_info.output_hash, hex::encode(expected_output_hash));
}
