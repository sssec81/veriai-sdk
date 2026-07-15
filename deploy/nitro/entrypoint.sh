#!/bin/bash
set -euo pipefail

/usr/local/bin/chat-demo &
chat_pid=$!

cleanup() {
  kill "${chat_pid}" "${relay_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

socat "VSOCK-LISTEN:${VSOCK_PORT},reuseaddr,fork" TCP:127.0.0.1:3000 &
relay_pid=$!

while kill -0 "${chat_pid}" 2>/dev/null && kill -0 "${relay_pid}" 2>/dev/null; do
  sleep 1
done

exit 1
