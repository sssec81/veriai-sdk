use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;
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
const CHALLENGE_TTL_SECONDS: u64 = 300;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct AppState {
    expected_pcr0: Arc<[u8]>,
    verifier: Arc<Verifier>,
    replay_state_path: Option<PathBuf>,
    replay_write_lock: Arc<tokio::sync::Mutex<()>>,
    require_issued_challenge: bool,
}

#[derive(Deserialize, Debug, Clone)]
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
    api_version: &'static str,
    version: &'static str,
    receipt_format: &'static str,
}

#[derive(Serialize, Debug)]
struct ChallengeResponse {
    nonce: String,
    expires_at: u64,
}

struct ChallengeReservation {
    available_path: PathBuf,
    reserved_path: PathBuf,
}

impl ChallengeReservation {
    fn restore(self) -> Result<(), String> {
        std::fs::rename(self.reserved_path, self.available_path)
            .map_err(|e| format!("failed to restore challenge: {e}"))
    }

    fn consume(self) -> Result<(), String> {
        std::fs::remove_file(self.reserved_path)
            .map_err(|e| format!("failed to consume challenge: {e}"))
    }
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    code: &'static str,
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
    let replay_state_path = std::env::var_os("STATE_FILE_PATH").map(PathBuf::from);
    let stateful = replay_state_path.is_some()
        || std::env::var("STATEFUL_VERIFICATION")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
    let verifier = Verifier::from_pem(configured_provider(), &trusted_root_pem, stateful)
        .unwrap_or_else(|e| panic!("Trusted root configuration is invalid: {e}"));
    if let Some(path) = replay_state_path.as_deref().filter(|path| path.exists()) {
        let saved_state = load_replay_state(path)
            .unwrap_or_else(|e| panic!("Replay state configuration is invalid: {e}"));
        verifier
            .set_state(saved_state)
            .unwrap_or_else(|e| panic!("Replay state could not be restored: {e}"));
    }
    let state = AppState {
        expected_pcr0: Arc::from(expected_pcr0),
        verifier: Arc::new(verifier),
        replay_state_path,
        replay_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        require_issued_challenge: cfg!(feature = "real-hardware"),
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/version", get(version_handler))
        .route("/v1/challenge", post(challenge_handler))
        .route("/v1/verify", post(verify_handler))
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
        api_version: "v1",
        version: env!("CARGO_PKG_VERSION"),
        receipt_format: "v1",
    })
}

async fn challenge_handler(
    State(state): State<AppState>,
) -> Result<Json<ChallengeResponse>, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let state_path = state
        .replay_state_path
        .as_deref()
        .ok_or_else(|| api_replay_error("STATE_FILE_PATH is required for issued challenges"))?;
    let expires_at = unix_seconds()
        .map_err(replay_state_http_error)?
        .checked_add(CHALLENGE_TTL_SECONDS)
        .ok_or_else(|| api_replay_error("challenge expiry overflow"))?;
    let directory = challenge_directory(state_path)?;
    std::fs::create_dir_all(&directory).map_err(replay_state_http_error)?;
    #[cfg(unix)]
    std::fs::set_permissions(
        &directory,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(replay_state_http_error)?;

    for _ in 0..8 {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let path = directory.join(hex::encode(nonce));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                #[cfg(unix)]
                file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))
                    .map_err(replay_state_http_error)?;
                writeln!(file, "{expires_at}").map_err(replay_state_http_error)?;
                file.sync_all().map_err(replay_state_http_error)?;
                return Ok(Json(ChallengeResponse {
                    nonce: hex::encode(nonce),
                    expires_at,
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(replay_state_http_error(error)),
        }
    }
    Err(api_replay_error("failed to allocate a unique challenge"))
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
                    code: "invalid_encoding",
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
                code: "invalid_model_hash",
                error: format!("Invalid model_hash: {}", e),
            }),
        )
    })?;

    let input_hash = decode_hex_32(&payload.input_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_input_hash",
                error: format!("Invalid input_hash: {}", e),
            }),
        )
    })?;

    let output_hash = decode_hex_32(&payload.output_hash).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_output_hash",
                error: format!("Invalid output_hash: {}", e),
            }),
        )
    })?;

    let nonce = decode_hex_32(&payload.nonce).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "invalid_nonce",
                error: format!("Invalid nonce: {}", e),
            }),
        )
    })?;

    // A stable sibling lock file coordinates independent verifier-service
    // processes on one host.  Never lock the state file itself: atomic rename
    // would replace its inode and invalidate an advisory lock.
    let replay_guard = if state.replay_state_path.is_some() {
        Some(state.replay_write_lock.lock().await)
    } else {
        None
    };
    let replay_file_lock = if let Some(path) = state.replay_state_path.as_deref() {
        let lock_path = replay_lock_path(path)?;
        let lock = tokio::task::spawn_blocking(move || acquire_replay_lock(&lock_path))
            .await
            .map_err(replay_state_http_error)?
            .map_err(replay_state_http_error)?;
        // A different process may have committed while this process waited.
        // Reload inside the inter-process transaction before sequence checking.
        if path.exists() {
            state
                .verifier
                .set_state(load_replay_state(path).map_err(replay_state_http_error)?)
                .map_err(replay_state_http_error)?;
        }
        Some(lock)
    } else {
        None
    };
    let challenge_reservation = if state.require_issued_challenge {
        let path = state
            .replay_state_path
            .as_deref()
            .ok_or_else(|| api_replay_error("STATE_FILE_PATH is required in real-hardware mode"))?;
        Some(reserve_challenge(path, nonce).map_err(|error| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    code: "invalid_challenge",
                    error,
                }),
            )
        })?)
    } else {
        None
    };
    let previous_replay_state = if replay_guard.is_some() {
        state.verifier.get_state().map_err(|error| {
            tracing::error!("Failed to snapshot replay state: {error}");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    code: "replay_state_error",
                    error: "Replay state is unavailable".to_string(),
                }),
            )
        })?
    } else {
        None
    };

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
                    code: "verification_error",
                    error: format!("Infrastructure error: {:?}", e),
                }),
            )
        })?;

    if !result.valid {
        if let Some(reservation) = challenge_reservation {
            reservation.restore().map_err(replay_state_http_error)?;
        }
        drop(replay_file_lock);
        drop(replay_guard);
        return Ok(Json(result));
    }

    if let Some(path) = state.replay_state_path.as_deref()
        && let Err(error) = persist_replay_state_or_rollback(
            &state.verifier,
            path,
            previous_replay_state.unwrap_or_default(),
        )
        .await
    {
        if let Some(reservation) = challenge_reservation {
            reservation.restore().map_err(replay_state_http_error)?;
        }
        tracing::error!("Failed to persist replay state: {error}");
        return Err((
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                code: "replay_state_error",
                error: "Verification succeeded but replay state could not be persisted".to_string(),
            }),
        ));
    }
    if let Some(reservation) = challenge_reservation {
        reservation.consume().map_err(replay_state_http_error)?;
    }
    drop(replay_guard);
    drop(replay_file_lock);

    tracing::info!("Verification completed. Valid: {}", result.valid);
    Ok(Json(result))
}

fn replay_lock_path(path: &Path) -> Result<PathBuf, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| api_replay_error("state file path must end in a file name"))?;
    Ok(path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.lock")))
}

fn acquire_replay_lock(path: &Path) -> Result<std::fs::File, String> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| format!("failed to open replay lock: {e}"))?;
    lock.lock_exclusive()
        .map_err(|e| format!("failed to acquire replay lock: {e}"))?;
    Ok(lock)
}

fn challenge_directory(
    state_path: &Path,
) -> Result<PathBuf, (axum::http::StatusCode, Json<ErrorResponse>)> {
    let name = state_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| api_replay_error("state file path must end in a file name"))?;
    Ok(state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{name}.challenges")))
}

fn unix_seconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("system clock error: {e}"))
}

fn reserve_challenge(state_path: &Path, nonce: [u8; 32]) -> Result<ChallengeReservation, String> {
    let directory = challenge_directory(state_path).map_err(|(_, body)| body.0.error)?;
    let available_path = directory.join(hex::encode(nonce));
    let expires_at = std::fs::read_to_string(&available_path)
        .map_err(|_| "challenge was not issued or was already consumed".to_string())?
        .trim()
        .parse::<u64>()
        .map_err(|_| "challenge record is invalid".to_string())?;
    if unix_seconds()? > expires_at {
        let _ = std::fs::remove_file(&available_path);
        return Err("challenge has expired".to_string());
    }
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let reserved_path = directory.join(format!(
        ".{}.{}.{}.reserved",
        hex::encode(nonce),
        std::process::id(),
        counter
    ));
    std::fs::rename(&available_path, &reserved_path)
        .map_err(|_| "challenge was concurrently consumed".to_string())?;
    Ok(ChallengeReservation {
        available_path,
        reserved_path,
    })
}

fn api_replay_error(message: impl Into<String>) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "replay_state_error",
            error: message.into(),
        }),
    )
}

fn replay_state_http_error(
    error: impl std::fmt::Display,
) -> (axum::http::StatusCode, Json<ErrorResponse>) {
    tracing::error!("Replay state failure: {error}");
    api_replay_error("Replay state is unavailable")
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
        validate_configured_roots(&pem)?;
        return Ok(pem);
    }
    let path = std::env::var("TRUSTED_ROOT_CERT_PATH")
        .map_err(|_| "set TRUSTED_ROOT_CERT_PEM or TRUSTED_ROOT_CERT_PATH".to_string())?;
    let pem =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read trusted root: {e}"))?;
    validate_configured_roots(&pem)?;
    Ok(pem)
}

fn validate_configured_roots(pem: &str) -> Result<(), String> {
    #[cfg(feature = "real-hardware")]
    veriai_attestation::validate_aws_nitro_root_pem(pem)?;
    #[cfg(not(feature = "real-hardware"))]
    let _ = pem;
    Ok(())
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

fn load_replay_state(path: &Path) -> Result<HashMap<[u8; 32], u64>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("failed to read state file: {e}"))?;
    let saved: HashMap<String, u64> =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid state JSON: {e}"))?;
    saved
        .into_iter()
        .map(|(fingerprint, sequence)| {
            let fingerprint = decode_hex_32(&fingerprint)
                .map_err(|e| format!("invalid identity fingerprint: {e}"))?;
            Ok((fingerprint, sequence))
        })
        .collect()
}

async fn persist_replay_state(verifier: &Verifier, path: &Path) -> Result<(), String> {
    let state = verifier
        .get_state()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "stateful verification is disabled".to_string())?;
    let encoded: HashMap<String, u64> = state
        .into_iter()
        .map(|(fingerprint, sequence)| (hex::encode(fingerprint), sequence))
        .collect();
    let bytes = serde_json::to_vec_pretty(&encoded)
        .map_err(|e| format!("failed to encode replay state: {e}"))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "state file path must end in a file name".to_string())?;
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        counter
    ));

    let mut temporary_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .await
        .map_err(|e| format!("failed to create replay state temporary file: {e}"))?;
    let write_result = async {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&temporary_path, std::fs::Permissions::from_mode(0o600))
                .await
                .map_err(|e| format!("failed to set replay state permissions: {e}"))?;
        }
        temporary_file
            .write_all(&bytes)
            .await
            .map_err(|e| format!("failed to write replay state: {e}"))?;
        temporary_file
            .sync_all()
            .await
            .map_err(|e| format!("failed to sync replay state: {e}"))?;
        drop(temporary_file);
        tokio::fs::rename(&temporary_path, path)
            .await
            .map_err(|e| format!("failed to replace replay state: {e}"))?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("failed to sync replay state directory: {e}"))
    }
    .await;

    if write_result.is_err() {
        let _ = tokio::fs::remove_file(&temporary_path).await;
    }
    write_result
}

async fn persist_replay_state_or_rollback(
    verifier: &Verifier,
    path: &Path,
    previous_state: HashMap<[u8; 32], u64>,
) -> Result<(), String> {
    if let Err(persist_error) = persist_replay_state(verifier, path).await {
        verifier
            .set_state(previous_state)
            .map_err(|rollback_error| {
                format!("{persist_error}; replay state rollback also failed: {rollback_error}")
            })?;
        return Err(persist_error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AppState, VerifyRequest, challenge_handler, load_replay_state, persist_replay_state,
        persist_replay_state_or_rollback, verify_handler,
    };
    use axum::{Json, extract::State};
    use base64ct::{Base64, Encoding};
    use std::collections::HashMap;
    use std::sync::Arc;
    use veriai_attestation::mock::MockAttestationProvider;
    use veriai_core::receipt::ReceiptGenerator;
    use veriai_core::verify::Verifier;

    const MOCK_ROOT_PEM: &str = include_str!("../../../tests/fixtures/mock-aws-root.pem");

    #[tokio::test]
    async fn replay_state_round_trips_through_atomic_file() {
        let verifier = Verifier::from_pem(
            Arc::new(MockAttestationProvider::new()),
            MOCK_ROOT_PEM,
            true,
        )
        .unwrap();
        let expected = HashMap::from([([0x42; 32], 7)]);
        verifier.set_state(expected.clone()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("replay-state.json");

        persist_replay_state(&verifier, &path).await.unwrap();

        assert_eq!(load_replay_state(&path).unwrap(), expected);
    }

    #[tokio::test]
    async fn replay_state_rolls_back_when_persistence_fails() {
        let verifier = Verifier::from_pem(
            Arc::new(MockAttestationProvider::new()),
            MOCK_ROOT_PEM,
            true,
        )
        .unwrap();
        let previous = HashMap::from([([0x42; 32], 7)]);
        verifier
            .set_state(HashMap::from([([0x42; 32], 8)]))
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("missing-parent/replay-state.json");

        assert!(
            persist_replay_state_or_rollback(&verifier, &path, previous.clone())
                .await
                .is_err()
        );
        assert_eq!(verifier.get_state().unwrap().unwrap(), previous);
    }

    fn app_state(path: std::path::PathBuf, require_issued_challenge: bool) -> AppState {
        AppState {
            expected_pcr0: Arc::from(vec![0u8; 48]),
            verifier: Arc::new(
                Verifier::from_pem(
                    Arc::new(MockAttestationProvider::new()),
                    MOCK_ROOT_PEM,
                    true,
                )
                .unwrap(),
            ),
            replay_state_path: Some(path),
            replay_write_lock: Arc::new(tokio::sync::Mutex::new(())),
            require_issued_challenge,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_service_instances_accept_a_receipt_only_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let provider = Arc::new(MockAttestationProvider::new());
        let generator = ReceiptGenerator::new(provider);
        let receipt = generator
            .generate_receipt([1; 32], [2; 32], [3; 32], [4; 32])
            .await
            .unwrap();
        let request = VerifyRequest {
            receipt: Base64::encode_string(&receipt),
            model_hash: hex::encode([1; 32]),
            input_hash: hex::encode([2; 32]),
            output_hash: hex::encode([3; 32]),
            nonce: hex::encode([4; 32]),
        };
        let first = verify_handler(State(app_state(path.clone(), false)), Json(request.clone()));
        let second = verify_handler(State(app_state(path, false)), Json(request));
        let (first, second) = tokio::join!(first, second);
        let accepted = [first, second]
            .into_iter()
            .filter(|result| result.as_ref().is_ok_and(|json| json.0.valid))
            .count();
        assert_eq!(accepted, 1);
    }

    #[tokio::test]
    async fn issued_challenge_is_consumed_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let response = challenge_handler(State(app_state(path.clone(), true)))
            .await
            .unwrap();
        let nonce: [u8; 32] = hex::decode(&response.nonce).unwrap().try_into().unwrap();
        let generator = ReceiptGenerator::new(Arc::new(MockAttestationProvider::new()));
        let receipt = generator
            .generate_receipt([1; 32], [2; 32], [3; 32], nonce)
            .await
            .unwrap();
        let request = VerifyRequest {
            receipt: Base64::encode_string(&receipt),
            model_hash: hex::encode([1; 32]),
            input_hash: hex::encode([2; 32]),
            output_hash: hex::encode([3; 32]),
            nonce: hex::encode(nonce),
        };
        let first = verify_handler(State(app_state(path.clone(), true)), Json(request.clone()))
            .await
            .unwrap();
        assert!(first.valid);
        assert!(
            verify_handler(State(app_state(path, true)), Json(request))
                .await
                .is_err()
        );
    }
}
