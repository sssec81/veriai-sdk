use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::verify::Verifier;
use veriai_types::VerificationResult;

#[derive(Deserialize, Debug)]
struct VerifyRequest {
    receipt: String,        // Base64 or Hex encoded receipt bytes
    model_hash: String,     // Hex encoded model hash
    input_hash: String,     // Hex encoded input hash
    output_hash: String,    // Hex encoded output hash
    nonce: String,          // Hex encoded client nonce
    expected_pcr0: String,  // Hex encoded expected PCR0
    root_cert: String,      // Trusted Root CA PEM
    stateful: Option<bool>, // Enable sequence monotonicity check
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

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/version", get(version_handler))
        .route("/verify", post(verify_handler))
        .layer(TraceLayer::new_for_http());

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
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<VerificationResult>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    tracing::info!("Received verify request");

    // Decode receipt (supports both Base64 and Hex)
    let receipt_bytes = if let Ok(bytes) = hex::decode(&payload.receipt) {
        bytes
    } else {
        use base64ct::{Base64, Encoding};
        Base64::decode_vec(&payload.receipt)
            .map_err(|e| {
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
            Json(ErrorResponse { error: format!("Invalid model_hash: {}", e) }),
        )
    })?;

    let input_hash = decode_hex_32(&payload.input_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid input_hash: {}", e) }),
        )
    })?;

    let output_hash = decode_hex_32(&payload.output_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid output_hash: {}", e) }),
        )
    })?;

    let nonce = decode_hex_32(&payload.nonce).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid nonce: {}", e) }),
        )
    })?;

    let expected_pcr0 = hex::decode(&payload.expected_pcr0).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid expected_pcr0 hex: {:?}", e) }),
        )
    })?;

    let provider = Arc::new(MockAttestationProvider::new());
    let stateful = payload.stateful.unwrap_or(false);

    let verifier = Verifier::from_pem(provider, &payload.root_cert, stateful).map_err(|e| {
        tracing::warn!("Invalid root certificate PEM: {}", e);
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid root_cert: {}", e) }),
        )
    })?;

    let result = verifier.verify(
        &receipt_bytes,
        model_hash,
        input_hash,
        output_hash,
        nonce,
        &expected_pcr0,
    ).await.map_err(|e| {
        tracing::error!("Cryptographic infrastructure error during verification: {:?}", e);
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: format!("Infrastructure error: {:?}", e) }),
        )
    })?;

    tracing::info!("Verification completed. Valid: {}", result.valid);
    Ok(Json(result))
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
