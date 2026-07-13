#!/bin/bash
set -e

echo "=== VeriAI SDK CLI Demo ==="

# Build the project
cargo build --manifest-path veriai-sdk/Cargo.toml --features mock-hardware

# Define executable path
VERIAI="./veriai-sdk/target/debug/veriai"

# Create temporary test files
echo "initializing model file..."
echo "model parameters: [0.1, 0.5, 0.9, -0.2]" > dummy_model.bin

echo "initializing input file..."
echo "user input: hello veriai" > dummy_input.txt

echo "initializing output file..."
echo "agent response: status ok" > dummy_output.txt

NONCE=$(openssl rand -hex 32)
PCR0=$(openssl rand -hex 48) # Mock verifier uses any PCR0 that matches the argument

echo "Nonce generated: $NONCE"

# 1. Generate Receipt
echo "--> Generating receipt..."
$VERIAI generate \
  --model dummy_model.bin \
  --input-file dummy_input.txt \
  --output-file dummy_output.txt \
  --nonce $NONCE \
  --receipt-out receipt.cose

echo "Receipt created successfully!"

# 2. Verify Receipt (Should succeed)
echo "--> Verifying receipt (expected success)..."
$VERIAI verify \
  --receipt receipt.cose \
  --model dummy_model.bin \
  --input-file dummy_input.txt \
  --output-file dummy_output.txt \
  --nonce $NONCE \
  --expected-pcr0 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  --root-cert veriai-sdk/tests/fixtures/mock-aws-root.pem

echo "Verification succeeded!"

# 3. Verify with wrong input (Should fail)
echo "--> Verifying with tampered input (expected failure)..."
echo "tampered" > tampered_input.txt
if $VERIAI verify \
  --receipt receipt.cose \
  --model dummy_model.bin \
  --input-file tampered_input.txt \
  --output-file dummy_output.txt \
  --nonce $NONCE \
  --expected-pcr0 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 \
  --root-cert veriai-sdk/tests/fixtures/mock-aws-root.pem 2>/dev/null; then
    echo "ERROR: Verification succeeded but should have failed!"
    exit 1
else
    echo "Verification failed as expected (tampered input detected)."
fi

# Clean up
rm -f dummy_model.bin dummy_input.txt dummy_output.txt tampered_input.txt receipt.cose
echo "=== Demo completed successfully ==="
