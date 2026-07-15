#!/bin/bash
set -euo pipefail

exec socat \
  "TCP-LISTEN:${PROXY_PORT:-3000},bind=127.0.0.1,reuseaddr,fork" \
  "VSOCK-CONNECT:${ENCLAVE_CID:-16}:${VSOCK_PORT:-3000}"
