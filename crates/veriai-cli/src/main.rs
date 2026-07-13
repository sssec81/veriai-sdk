use clap::{Parser, Subcommand};
use coset::{CborSerializable, CoseSign1};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use veriai_attestation::mock::MockAttestationProvider;
use veriai_core::hashing::compute_model_hash;
use veriai_core::receipt::ReceiptGenerator;
use veriai_core::verify::Verifier;
use veriai_types::VeriClaims;

#[derive(Parser)]
#[command(name = "veriai")]
#[command(version = "0.1.0")]
#[command(about = "VeriAI CLI tool for verifiable AI inference", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect details of a signed COSE receipt
    Inspect {
        /// Path to the receipt file
        receipt: PathBuf,
    },
    /// Verify a signed COSE receipt
    Verify {
        /// Path to the binary COSE receipt file
        #[arg(short, long)]
        receipt: PathBuf,

        /// Path to the model file to recompute and verify Merkle root
        #[arg(short, long)]
        model: PathBuf,

        /// Path to the input file to verify (if omitted, reads from stdin)
        #[arg(short, long)]
        input_file: Option<PathBuf>,

        /// Path to the output file to verify (if omitted, reads from stdin)
        #[arg(short, long)]
        output_file: Option<PathBuf>,

        /// Hex-encoded 32-byte expected client nonce
        #[arg(long)]
        nonce: String,

        /// Hex-encoded 48-byte expected PCR0 value
        #[arg(long)]
        expected_pcr0: String,

        /// Path to the trusted Root CA certificate PEM file
        #[arg(short = 'c', long)]
        root_cert: PathBuf,

        /// Optional path to a JSON session file for stateful sequence validation
        #[arg(short, long)]
        stateful: Option<PathBuf>,
    },
    /// Generate a signed COSE receipt (for testing/development)
    Generate {
        /// Path to the model file (weights) to compute Merkle root
        #[arg(short, long)]
        model: PathBuf,

        /// Path to the input file (if omitted, reads from stdin)
        #[arg(short, long)]
        input_file: Option<PathBuf>,

        /// Path to the output file (if omitted, reads from stdin)
        #[arg(short, long)]
        output_file: Option<PathBuf>,

        /// Hex-encoded 32-byte client nonce (if omitted, a random one is generated)
        #[arg(long)]
        nonce: Option<String>,

        /// Path to save the generated binary COSE receipt
        #[arg(short, long)]
        receipt_out: PathBuf,
    },
}

fn read_bytes_or_stdin(path: Option<PathBuf>) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    if let Some(p) = path {
        let mut file = File::open(p)?;
        file.read_to_end(&mut buffer)?;
    } else {
        io::stdin().read_to_end(&mut buffer)?;
    }
    Ok(buffer)
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_any(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Use MockAttestationProvider for CLI (or Nitro depending on compile flags)
    let provider = Arc::new(MockAttestationProvider::new());

    match cli.command {
        Commands::Inspect { receipt } => {
            let receipt_bytes = fs::read(receipt)?;
            let cose_receipt = CoseSign1::from_slice(&receipt_bytes)
                .map_err(|e| format!("Cose parse error: {:?}", e))?;
            let payload = cose_receipt.payload.ok_or("Receipt contains no payload")?;
            let claims = VeriClaims::from_binary(&payload)
                .map_err(|e| format!("Claims parse error: {:?}", e))?;

            println!("VeriAI Receipt Inspection");
            println!("-------------------------");
            println!("SDK Version:       {}", claims.sdk_version);
            println!("Model Merkle Root: {}", hex::encode(claims.model_hash));
            println!("Input Hash:        {}", hex::encode(claims.input_hash));
            println!("Output Hash:       {}", hex::encode(claims.output_hash));
            println!("Client Nonce:      {}", hex::encode(claims.client_nonce));
            println!("Sequence Number:   {}", claims.sequence_num);
            println!("Timestamp:         {}", claims.attestation_timestamp);
            println!("Enclave Public Key:{}", hex::encode(claims.enclave_pubkey));
        }
        Commands::Generate {
            model,
            input_file,
            output_file,
            nonce,
            receipt_out,
        } => {
            println!("Computing model Merkle root...");
            let model_hash = compute_model_hash(&model)?;
            println!("Model Merkle root: {}", hex::encode(model_hash));

            let input_bytes = read_bytes_or_stdin(input_file)?;
            let output_bytes = read_bytes_or_stdin(output_file)?;

            let input_hash: [u8; 32] = Sha256::digest(&input_bytes).into();
            let output_hash: [u8; 32] = Sha256::digest(&output_bytes).into();

            let nonce_bytes = match nonce {
                Some(hex_str) => parse_hex_32(&hex_str)?,
                None => {
                    use rand_core::RngCore;
                    let mut rng = rand_core::OsRng;
                    let mut n = [0u8; 32];
                    rng.fill_bytes(&mut n);
                    n
                }
            };

            let generator = ReceiptGenerator::new(provider.clone());
            let receipt = generator
                .generate_receipt(model_hash, input_hash, output_hash, nonce_bytes)
                .await?;

            fs::write(&receipt_out, receipt)?;
            println!(
                "Receipt generated successfully and saved to {:?}",
                receipt_out
            );
        }
        Commands::Verify {
            receipt,
            model,
            input_file,
            output_file,
            nonce,
            expected_pcr0,
            root_cert,
            stateful,
        } => {
            let receipt_bytes = fs::read(&receipt)?;

            println!("Recomputing model Merkle root...");
            let model_hash = compute_model_hash(&model)?;

            let input_bytes = read_bytes_or_stdin(input_file)?;
            let output_bytes = read_bytes_or_stdin(output_file)?;

            let input_hash: [u8; 32] = Sha256::digest(&input_bytes).into();
            let output_hash: [u8; 32] = Sha256::digest(&output_bytes).into();

            let nonce_bytes = parse_hex_32(&nonce)?;
            let pcr0_bytes = parse_hex_any(&expected_pcr0)?;

            let root_pem = fs::read_to_string(&root_cert)?;
            let use_stateful = stateful.is_some();
            let verifier = Verifier::from_pem(provider.clone(), &root_pem, use_stateful)?;

            // Load saved state if stateful and session file exists
            if let Some(ref session_path) = stateful.as_ref().filter(|p| p.exists()) {
                let file = File::open(session_path)?;
                let saved_state: HashMap<String, u64> = serde_json::from_reader(file)?;
                let mut decoded_state = HashMap::new();
                for (k, v) in saved_state {
                    let bytes = hex::decode(&k)?;
                    let mut fp = [0u8; 32];
                    if bytes.len() == 32 {
                        fp.copy_from_slice(&bytes);
                        decoded_state.insert(fp, v);
                    }
                }
                verifier.set_state(decoded_state);
            }

            println!("\nVeriAI Receipt Verification");
            println!("---------------------------");

            let result = verifier
                .verify(
                    &receipt_bytes,
                    model_hash,
                    input_hash,
                    output_hash,
                    nonce_bytes,
                    &pcr0_bytes,
                )
                .await?;

            for check in &result.checks {
                let status_symbol = if check.status == "passed" {
                    "✓"
                } else {
                    "✗"
                };
                if let Some(ref details) = check.details {
                    println!("{} {} ({})", status_symbol, check.name, details);
                } else {
                    println!("{} {}", status_symbol, check.name);
                }
            }

            println!(
                "\nResult: {}",
                if result.valid { "VERIFIED" } else { "FAILED" }
            );

            if !result.valid {
                if let Some(err) = result.error {
                    println!("Reason: {}", err);
                }
                std::process::exit(1);
            }

            // Save updated state if stateful
            if let Some((session_path, state_map)) = stateful.as_ref().zip(verifier.get_state()) {
                let hex_state: HashMap<String, u64> = state_map
                    .into_iter()
                    .map(|(k, v)| (hex::encode(k), v))
                    .collect();
                let file = File::create(session_path)?;
                serde_json::to_writer_pretty(file, &hex_state)?;
            }
        }
    }

    Ok(())
}
