# VeriAI WASM verifier

This crate verifies receipt signatures, attestation chains, PCR0, nonce binding,
and model/input/output hashes without access to `/dev/nsm`.

The API is stateless. It cannot detect a receipt replayed across calls. The
application using this module must issue unique nonces and retain them, or keep
equivalent replay state on a server.

The trusted root and expected PCR0 are verifier policy. Do not copy either value
from the response being verified.

Build for a browser with:

```bash
rustup target add wasm32-unknown-unknown
cargo build -p veriai-wasm --target wasm32-unknown-unknown --release
```

CI currently enforces a 350 KB gzip ceiling. The original 200 KB planning
target has not been reached with full P-384 and X.509 chain validation; reducing
that size remains follow-up work.
