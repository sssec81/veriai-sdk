use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::PathBuf;
use veriai_sdk::hashing::compute_model_hash;
use veriai_sdk::receipt::ReceiptGenerator;
use veriai_sdk::verify::Verifier;

#[derive(Parser)]
#[command(name = "veriai")]
#[command(about = "VeriAI SDK Command Line Interface", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a signed COSE receipt inside the enclave
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
    /// Verify a signed COSE receipt
    Verify {
        /// Path to the binary COSE receipt file
        #[arg(short, long)]
        receipt: PathBuf,

        /// Path to the model file to recompute and verify Merkle root
        #[arg(short, long)]
        model: PathBuf,

        /// Path to the input file to verify
        #[arg(short, long)]
        input_file: Option<PathBuf>,

        /// Path to the output file to verify
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
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

            // Load input & output bytes
            let input_bytes = read_bytes_or_stdin(input_file)?;
            let output_bytes = read_bytes_or_stdin(output_file)?;

            let input_hash: [u8; 32] = Sha256::digest(&input_bytes).into();
            let output_hash: [u8; 32] = Sha256::digest(&output_bytes).into();

            // Decode or generate nonce
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
            println!("Client nonce: {}", hex::encode(nonce_bytes));

            // Initialize Receipt Generator and build receipt
            let generator = ReceiptGenerator::new();
            let receipt = generator.generate_receipt(
                model_hash,
                input_hash,
                output_hash,
                nonce_bytes,
            )?;

            // Save receipt
            fs::write(&receipt_out, receipt)?;
            println!("Receipt generated successfully and saved to {:?}", receipt_out);
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
            // Load receipt
            let receipt_bytes = fs::read(&receipt)?;

            println!("Recomputing model Merkle root...");
            let model_hash = compute_model_hash(&model)?;
            println!("Model Merkle root: {}", hex::encode(model_hash));

            let input_bytes = read_bytes_or_stdin(input_file)?;
            let output_bytes = read_bytes_or_stdin(output_file)?;

            let input_hash: [u8; 32] = Sha256::digest(&input_bytes).into();
            let output_hash: [u8; 32] = Sha256::digest(&output_bytes).into();

            let nonce_bytes = parse_hex_32(&nonce)?;
            let pcr0_bytes = parse_hex_any(&expected_pcr0)?;

            // Read root CA PEM
            let root_pem = fs::read_to_string(&root_cert)?;

            // Configure stateful sequence verifier if requested
            let use_stateful = stateful.is_some();
            let verifier = Verifier::from_pem(&root_pem, use_stateful)?;

            // Load saved state if stateful and session file exists
            if let Some(ref session_path) = stateful {
                if session_path.exists() {
                    let file = File::open(session_path)?;
                    let saved_state: HashMap<String, u64> = serde_json::from_reader(file)?;
                    
                    // Decode hex strings back into raw binary fingerprints
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
            }

            // Perform verification
            verifier.verify(
                &receipt_bytes,
                model_hash,
                input_hash,
                output_hash,
                nonce_bytes,
                &pcr0_bytes,
            )?;

            // Save updated state if stateful
            if let Some(ref session_path) = stateful {
                // Get state from verifier and save to JSON
                // We'll write state-accessor helpers on Verifier.
                if let Some(state_map) = verifier.get_state() {
                    // Encode keys as hex for JSON compatibility
                    let hex_state: HashMap<String, u64> = state_map
                        .into_iter()
                        .map(|(k, v)| (hex::encode(k), v))
                        .collect();
                    let file = File::create(session_path)?;
                    serde_json::to_writer_pretty(file, &hex_state)?;
                }
            }

            println!("Receipt verification succeeded! Cryptographic proof is VALID.");
        }
    }

    Ok(())
}
