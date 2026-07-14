use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use veriai_attestation::AttestationProvider;
#[cfg(feature = "mock-hardware")]
use veriai_attestation::mock::MockAttestationProvider;
#[cfg(feature = "real-hardware")]
use veriai_attestation::nitro::NitroAttestationProvider;
use veriai_core::verify::Verifier;
use veriai_types::VerificationResult;

const MAX_REQUEST_BODY: usize = 128 * 1024;

#[derive(Clone)]
struct AppState {
    expected_pcr0: Arc<[u8]>,
    verifier: Arc<Verifier>,
}

#[derive(Deserialize, Debug)]
struct VerifyRequest {
    receipt: String,     // Base64 or Hex encoded receipt bytes
    model_hash: String,  // Hex encoded model hash
    input_hash: String,  // Hex encoded input hash
    output_hash: String, // Hex encoded output hash
    nonce: String,       // Hex encoded client nonce
}

#[derive(Serialize, Debug)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize, Debug)]
struct VersionResponse {
    version: &'static str,
    receipt_format: &'static str,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let trusted_root_pem = load_trusted_root()
        .unwrap_or_else(|e| panic!("Trusted root configuration is invalid: {e}"));
    let expected_pcr0 = load_expected_pcr0()
        .unwrap_or_else(|e| panic!("Expected PCR0 configuration is invalid: {e}"));
    let stateful = std::env::var("STATEFUL_VERIFICATION")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let verifier = Verifier::from_pem(configured_provider(), &trusted_root_pem, stateful)
        .unwrap_or_else(|e| panic!("Trusted root configuration is invalid: {e}"));
    let state = AppState {
        expected_pcr0: Arc::from(expected_pcr0),
        verifier: Arc::new(verifier),
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/version", get(version_handler))
        .route("/verify", post(verify_handler))
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY))
        .with_state(state);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("Invalid PORT");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("VeriAI Verifier Service running on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn version_handler() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        receipt_format: "v1",
    })
}

async fn verify_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerificationResult>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    tracing::info!("Received verify request");

    // Decode receipt (supports both Base64 and Hex)
    let receipt_bytes = if let Ok(bytes) = hex::decode(&payload.receipt) {
        bytes
    } else {
        use base64ct::{Base64, Encoding};
        Base64::decode_vec(&payload.receipt).map_err(|e| {
            tracing::warn!("Failed to decode receipt: {:?}", e);
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Invalid receipt encoding (must be hex or base64): {:?}", e),
                }),
            )
        })?
    };

    // Decode parameter hexes
    let model_hash = decode_hex_32(&payload.model_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid model_hash: {}", e),
            }),
        )
    })?;

    let input_hash = decode_hex_32(&payload.input_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid input_hash: {}", e),
            }),
        )
    })?;

    let output_hash = decode_hex_32(&payload.output_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid output_hash: {}", e),
            }),
        )
    })?;

    let nonce = decode_hex_32(&payload.nonce).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid nonce: {}", e),
            }),
        )
    })?;

    let result = state
        .verifier
        .verify(
            &receipt_bytes,
            model_hash,
            input_hash,
            output_hash,
            nonce,
            &state.expected_pcr0,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                "Cryptographic infrastructure error during verification: {:?}",
                e
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Infrastructure error: {:?}", e),
                }),
            )
        })?;

    tracing::info!("Verification completed. Valid: {}", result.valid);
    Ok(Json(result))
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

fn load_trusted_root() -> Result<String, String> {
    if let Ok(pem) = std::env::var("TRUSTED_ROOT_CERT_PEM")
        && pem.contains("BEGIN CERTIFICATE")
    {
        return Ok(pem);
    }
    let path = std::env::var("TRUSTED_ROOT_CERT_PATH")
        .map_err(|_| "set TRUSTED_ROOT_CERT_PEM or TRUSTED_ROOT_CERT_PATH".to_string())?;
    std::fs::read_to_string(path).map_err(|e| format!("failed to read trusted root: {e}"))
}

fn load_expected_pcr0() -> Result<Vec<u8>, String> {
    let value = std::env::var("EXPECTED_PCR0")
        .map_err(|_| "set EXPECTED_PCR0 to the 48-byte PCR0 hex value".to_string())?;
    let pcr0 = hex::decode(value).map_err(|e| format!("PCR0 is not valid hex: {e}"))?;
    if pcr0.len() != 48 {
        return Err(format!("PCR0 must be 48 bytes, got {}", pcr0.len()));
    }
    Ok(pcr0)
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("Hex decode failed: {:?}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
