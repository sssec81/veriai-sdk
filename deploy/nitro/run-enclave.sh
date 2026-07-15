#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."

nitro-cli run-enclave \
  --eif-path deploy/nitro/veriai.eif \
  --cpu-count "${ENCLAVE_CPU_COUNT:-2}" \
  --memory "${ENCLAVE_MEMORY_MIB:-4096}" \
  --enclave-cid "${ENCLAVE_CID:-16}"
