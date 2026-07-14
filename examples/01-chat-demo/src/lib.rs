use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use veriai_attestation::AttestationProvider;
#[cfg(feature = "mock-hardware")]
use veriai_attestation::mock::MockAttestationProvider;
#[cfg(feature = "real-hardware")]
use veriai_attestation::nitro::NitroAttestationProvider;
use veriai_core::hashing::compute_model_hash;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_runtime::{InferenceRuntime, LlamaCppRuntime, mock::MockRuntime};
use veriai_types::openai::{
    ChatCompletionRequest, ChatCompletionResponse, Choice, InferenceRequest, Message, Usage,
};

#[cfg(not(feature = "real-hardware"))]
const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

#[derive(Clone)]
struct AppState {
    runtime: Arc<dyn InferenceRuntime>,
    generator: Arc<ReceiptGenerator>,
    verifier: Arc<Verifier>,
    model_hash: [u8; 32],
    expected_pcr0: Arc<[u8]>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

pub fn app() -> Router {
    let state = build_state().unwrap_or_else(|error| panic!("failed to initialize demo: {error}"));
    Router::new()
        .route("/v1/chat/completions", post(chat_completions_handler))
        .with_state(state)
}

fn build_state() -> Result<AppState, String> {
    let provider: Arc<dyn AttestationProvider> = configured_provider();
    let (runtime, model_hash) = configured_runtime()?;
    let root_pem = configured_root_pem();
    let expected_pcr0 = configured_pcr0()?;
    let stateful = std::env::var("STATEFUL_VERIFICATION")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let generator = Arc::new(ReceiptGenerator::new(provider.clone()));
    let verifier = Arc::new(
        Verifier::from_pem(provider, &root_pem, stateful)
            .map_err(|error| format!("invalid trusted root: {error}"))?,
    );

    Ok(AppState {
        runtime,
        generator,
        verifier,
        model_hash,
        expected_pcr0: Arc::from(expected_pcr0),
    })
}

fn configured_runtime() -> Result<(Arc<dyn InferenceRuntime>, [u8; 32]), String> {
    let runtime_name = std::env::var("VERIAI_RUNTIME").unwrap_or_else(|_| {
        if cfg!(feature = "real-hardware") {
            "llama_cpp".to_string()
        } else {
            "mock".to_string()
        }
    });

    if runtime_name == "mock" {
        return Ok((Arc::new(MockRuntime::new()), [0x55; 32]));
    }
    if runtime_name != "llama_cpp" {
        return Err(format!("unsupported VERIAI_RUNTIME: {runtime_name}"));
    }

    let model_path = std::env::var("VERIAI_MODEL_PATH")
        .map_err(|_| "VERIAI_MODEL_PATH is required for llama_cpp runtime".to_string())?;
    let model_path = std::path::PathBuf::from(model_path);
    let model_hash = compute_model_hash(&model_path)
        .map_err(|error| format!("failed to hash model: {error}"))?;
    let binary = std::env::var("LLAMA_CLI_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("llama-cli"));

    Ok((
        Arc::new(LlamaCppRuntime::with_binary(model_path, binary)),
        model_hash,
    ))
}

fn configured_root_pem() -> String {
    #[cfg(feature = "real-hardware")]
    {
        if let Ok(pem) = std::env::var("TRUSTED_ROOT_CERT_PEM") {
            return pem;
        }
        let path = std::env::var("TRUSTED_ROOT_CERT_PATH")
            .expect("TRUSTED_ROOT_CERT_PATH or TRUSTED_ROOT_CERT_PEM is required");
        return std::fs::read_to_string(path).expect("failed to read trusted root certificate");
    }
    #[cfg(not(feature = "real-hardware"))]
    {
        MOCK_ROOT_PEM.to_string()
    }
}

fn configured_pcr0() -> Result<Vec<u8>, String> {
    #[cfg(feature = "real-hardware")]
    {
        let value = std::env::var("EXPECTED_PCR0")
            .map_err(|_| "EXPECTED_PCR0 is required for real hardware".to_string())?;
        let pcr0 = hex::decode(value).map_err(|error| format!("invalid EXPECTED_PCR0: {error}"))?;
        if pcr0.len() != 48 {
            return Err(format!(
                "EXPECTED_PCR0 must be 48 bytes, got {}",
                pcr0.len()
            ));
        }
        Ok(pcr0)
    }
    #[cfg(not(feature = "real-hardware"))]
    {
        Ok(vec![0u8; 48])
    }
}

fn configured_provider() -> Arc<dyn AttestationProvider> {
    #[cfg(feature = "real-hardware")]
    {
        Arc::new(NitroAttestationProvider::new())
    }
    #[cfg(all(feature = "mock-hardware", not(feature = "real-hardware")))]
    {
        Arc::new(MockAttestationProvider::new())
    }
}

async fn chat_completions_handler(
    State(state): State<AppState>,
    Json(payload): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, (StatusCode, Json<ErrorResponse>)> {
    if payload.model.trim().is_empty() || payload.messages.is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "model and at least one message are required",
        ));
    }

    let inference_req = InferenceRequest {
        messages: payload.messages,
        temperature: payload.temperature,
    };
    let canonical_input = inference_req.canonical_bytes().map_err(|error| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "serialization_error",
            error.to_string(),
        )
    })?;
    let inference_result = state
        .runtime
        .generate(inference_req)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "inference_error",
                error.to_string(),
            )
        })?;

    let input_hash: [u8; 32] = Sha256::digest(&canonical_input).into();
    let output_hash: [u8; 32] = Sha256::digest(inference_result.content.as_bytes()).into();
    let mut client_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut client_nonce);

    let receipt_bytes = state
        .generator
        .generate_receipt(state.model_hash, input_hash, output_hash, client_nonce)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "receipt_generation_error",
                error.to_string(),
            )
        })?;
    let verify_result = state
        .verifier
        .verify(
            &receipt_bytes,
            state.model_hash,
            input_hash,
            output_hash,
            client_nonce,
            &state.expected_pcr0,
        )
        .await
        .map_err(|error| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "verification_error",
                error.to_string(),
            )
        })?;

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let prompt_tokens = canonical_input.len().div_ceil(4) as u32;
    let completion_tokens = inference_result.tokens_generated;

    Ok(Json(ChatCompletionResponse {
        id: format!("chatcmpl-veriai-{created}"),
        object: "chat.completion".to_string(),
        created,
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
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
        verification: Some(verify_result),
    }))
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: ErrorBody {
                code,
                message: message.into(),
            },
        }),
    )
}
