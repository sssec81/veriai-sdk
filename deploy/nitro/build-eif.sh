#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

if [[ ! -f deploy/nitro/model.gguf ]]; then
  echo "Copy the GGUF model to deploy/nitro/model.gguf before building."
  exit 1
fi

docker build \
  --file deploy/nitro/Dockerfile.enclave \
  --tag veriai-enclave:latest \
  .

nitro-cli build-enclave \
  --docker-uri veriai-enclave:latest \
  --output-file deploy/nitro/veriai.eif \
  | tee deploy/nitro/measurements.json

echo "Review measurements.json and configure the external verifier with PCR0."
