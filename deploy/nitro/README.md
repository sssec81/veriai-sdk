# AWS Nitro deployment reference

These files build the real-hardware chat proxy into an Enclave Image File
(EIF). The model, `llama-cli`, proxy binary, and enclave-side vsock relay are
measured by PCR0 because they are inside the image. The parent-side relay is
outside the enclave and is not part of PCR0.

This must be run on a Linux EC2 parent instance that supports Nitro Enclaves.
Install Docker, the Nitro CLI, the enclave allocator service, and `socat` on the
parent first.

## Build

Copy the model into the build context, then build the EIF:

```bash
cp /path/to/model.gguf deploy/nitro/model.gguf
chmod +x deploy/nitro/*.sh
./deploy/nitro/build-eif.sh
```

The build writes `deploy/nitro/measurements.json`. Record PCR0 from this file in
the verifier policy. Rebuilding any part of the image can change PCR0.

## Run

Configure `/etc/nitro_enclaves/allocator.yaml` with enough CPU and memory, restart
the allocator service, then run:

```bash
./deploy/nitro/run-enclave.sh
./deploy/nitro/parent-relay.sh
```

The parent relay binds only to `127.0.0.1:3000`. Put authentication, TLS, request
limits, and any public load balancer in front of it; do not expose the relay
directly.

The enclave returns a base64 COSE receipt but does not verify its own receipt.
Run `verifier-service` outside the enclave with the AWS Nitro trusted root and
the PCR0 from `measurements.json`:

```bash
export TRUSTED_ROOT_CERT_PATH=/path/to/aws-nitro-root.pem
export EXPECTED_PCR0=<96-hex-characters-from-measurements.json>
export STATE_FILE_PATH=/var/lib/veriai/replay-state.json
cargo run -p verifier-service --no-default-features --features real-hardware
```

`STATE_FILE_PATH` uses an advisory lock and is safe for multiple verifier
processes sharing one local filesystem. It is not a distributed replay store;
use a transactional shared database before deploying multiple hosts.

The verifier listens on port 8080 by default. The parent relay forwards the
proxy request to the enclave on port 3000; place authentication and TLS in
front of the parent relay before exposing it outside the host.
`verifier-service` binds to `127.0.0.1` by default. Set `BIND_ADDR` only when a
trusted network boundary requires another address; public exposure still
requires authentication, TLS, request throttling, and monitoring upstream.

In real-hardware mode, obtain a short-lived verifier challenge before calling
the enclave proxy:

```bash
curl -s -X POST http://127.0.0.1:8080/v1/challenge
```

Send the returned `nonce` as `X-VeriAI-Nonce` to the proxy, then include the
same nonce in `/v1/verify`. The verifier atomically reserves the issued
challenge, restores it after invalid verification, and consumes it only after
successful verification and durable replay-state persistence. A consumed or
expired challenge is rejected.

## Security and reproducibility notes

- A fresh 32-byte client/verifier-issued nonce is required in real-hardware mode
  for every request. `verifier-service` issues five-minute challenges and
  consumes them once to provide a freshness guarantee.
- Docker base images are pinned by digest, Debian packages come from a dated
  snapshot, and the `llama.cpp` revision is pinned. Updating any of these inputs
  requires an explicit reviewed change and produces a new PCR0.
- The model file is intentionally ignored by Git.
- Successful local or mock verification is not evidence of Nitro hardware.
