# AWS Nitro deployment reference

These files build the real-hardware chat proxy into an Enclave Image File
(EIF). The model, `llama-cli`, proxy binary, and vsock relay are all measured by
PCR0 because they are inside the image.

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
the PCR0 from `measurements.json`.

## Security and reproducibility notes

- A fresh 32-byte client nonce should be supplied in `X-VeriAI-Nonce` for every
  request and retained by the verifier to prevent replay.
- The Docker base images and apt repositories are not digest-pinned in this
  reference. Pin them before treating PCR0 as a reproducible release artifact.
- The `llama.cpp` revision is pinned. Review and update it deliberately.
- The model file is intentionally ignored by Git.
- Successful local or mock verification is not evidence of Nitro hardware.
