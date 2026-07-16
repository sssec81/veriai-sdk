# VeriAI security notes

This is a working list of security risks and mitigations in the repository. It is not an independent security audit or a claim that the system is ready for production.

---

## 1. Risk Classification & Threat Matrix

| ID | Title | Severity | Impact | Mitigation Status |
| :--- | :--- | :---: | :--- | :--- |
| **SEC-01** | Missing Certificate Validity Checks | High | Expired leaf or intermediate certs accepted | **Implemented in code** (checks validity period across entire chain) |
| **SEC-02A**| Verifier State Replay (Reset/Scale) | Critical | Sequence bypass on verifier restart or horizontal scaling | **Partially implemented** (durable state plus an inter-process lock on one host; a transactional shared store remains required for horizontal scaling) |
| **SEC-02B**| Attestation Receipt Replay | Critical | Valid old receipts accepted forever | **Implemented in code** (maximum receipt age and timestamp checks) |
| **SEC-03** | Enclave Private Key Lifecycle Protection | Critical | Key theft if written to disk or cloned in memory | **Partially implemented** (`SigningKey` zeroization and enclave core-dump disablement are enabled; locked memory remains deployment work) |
| **SEC-04** | Resource Exhaustion (OOM) via CBOR/COSE | High | Denial of service via malicious large files | **Implemented in code** (receipt and HTTP body limits) |
| **SEC-05** | Replay State File / Symlink Attacks | High | Privilege escalation, file overwrite, or write corruption | **Partially implemented** (metadata cache removed; replay state uses create-new temporary files and atomic replacement) |
| **SEC-06** | Algorithm Agility Attacks | High | Downgrade to `none` or weaker signatures | **Implemented in code** (protected algorithm/content type required; unprotected and critical headers rejected) |
| **SEC-07** | Certificate Extension Validation | High | Impersonation using client auth certs | **Implemented in code** (checks `basicConstraints CA:true` on intermediates) |
| **SEC-08** | Root Certificate Pinning Brittleness | High | Service breakdown on AWS root CA rotations | **Implemented in code** (compiled AWS G1 fingerprint allowlist; rotations require a reviewed release update) |
| **SEC-09** | Input Ambiguity in Key Binding | High | Concatenation prefix collision attacks | **Not applicable** (the version, domain separator, and 32-byte key are fixed-width and unambiguous) |
| **SEC-10** | Release Build Mock Mode Drift | High | Shipping mock hardware backend to production | **Implemented in code** (compile-time check outside tests) |
| **SEC-11** | Missing Attestation Freshness Check | Critical | Replaying old valid attestation documents | **Implemented in code** (timestamp window plus verifier-issued, expiring, one-time challenges in real-hardware service mode) |
| **SEC-12** | Nonce Entropy Validation | High | Low-entropy or predictable nonces enabling replay | **Implemented for supplied flows** (demo and verifier challenge issuance use `OsRng`; real-hardware proxy requires a caller/verifier-issued nonce) |
| **SEC-13** | Memory Leakage & Exposure | Medium | Key leak through core dumps, debugging, or swap | **Follow-up** (use `mlock` and disable core dumps) |
| **SEC-14** | Dependency Supply Chain | Medium | Upstream library security vulnerabilities | **Implemented in CI configuration** (pinned `cargo audit`, `cargo deny`, and `cargo vet`; `serde_cbor` remains an explicitly visible unmaintained transitive dependency warning) |
| **SEC-15** | Merkle Tree Odd-Node Duplication | Medium | Hash collision vulnerabilities during inclusion proofs | **Documented** (the current hash is not an inclusion proof) |
| **SEC-16** | Model Replacement After Startup | Medium | A local model file can be swapped after the startup hash | **Partially implemented** (metadata-only cache removed; Nitro PCR0 must protect the model and proxy image) |
| **SEC-17** | Weak Trusted Roots Verification Path | Low | Defense-in-depth bypass if mixed roots list provided | **Documented** (callers must populate trusted roots correctly) |
| **SEC-18** | WASM Size Budget | Medium | Larger browser download and startup cost | **Follow-up** (full-chain build is below 350 KB gzipped but above the 200 KB planning target) |

---

## 2. Deep Dive Analysis & Mitigations

### 2.1 COSE / CBOR & Resource Exhaustion (SEC-04)
- **Problem**: Receiving untrusted large payload sizes before decoding leads to memory resource exhaustion (OOM).
- **Mitigation**: Implement a configurable limit inside `VerifierConfig` and check payload length before calling parser:
  ```rust
  pub struct VerifierConfig {
      pub max_receipt_size: usize, // Default to 64 KB
  }
  ```

### 2.2 Certificate Validation Completeness (SEC-01, SEC-07, SEC-08)
- **Problem**: Signature chain verification validates keys but misses temporal constraints (validity period), key usages, and CA rotations.
- **Mitigations**:
  1. **Temporal Chain Check**: Validate the `validity` window (NotBefore / NotAfter) on the leaf cert and all intermediate certs in the chain against system clock. **[Implemented & Verified]**
  2. **Certificate constraints**: Verify leaf/CA `BasicConstraints`, applicable `KeyUsage`, path length, issuer/subject linkage, validity, signatures, and reject unsupported critical extensions. **[Implemented and regression-tested for the Nitro profile]**
  3. **CA Bundle Ordering**: AWS provides `cabundle` root-first; validation reverses it while walking from leaf to root. **[Implemented]**
  4. **Fingerprint Set CA Pinning**: Real-hardware verifier roots must match a compiled AWS Nitro G1 fingerprint allowlist. **[Implemented]**

### 2.3 REPORTDATA input encoding (SEC-09)
The current input is unambiguous: a one-byte version, fixed domain separator,
and a fixed 32-byte Ed25519 key. Preserve it for receipt-format compatibility.

### 2.4 State Replay Protection & distributed Enclaves (SEC-02A, SEC-02B)
- **Problem**: A verifier restart or multiple verifier instances can lose or split sequence state.
- **Mitigations**:
1. **Single-host persistence**: `STATE_FILE_PATH` writes sequence state atomically and uses a stable sibling advisory lock. State is reloaded, verified, and persisted while the lock is held.
2. **Distributed Sequence Store**: Use a transactional shared database before horizontal scaling; filesystem locks are not a distributed protocol.
  3. **Receipt Expiration Check**: The verifier enforces a five-minute default maximum receipt age.

### 2.5 Private Key Lifecycle (SEC-03, SEC-13)
- **Problem**: Ephemeral signing keys could leak via core dumps, memory pages, or cloning.
- **Current state**: `ed25519-dalek` zeroizes the receipt signing key when it is
  dropped. Locked memory and core-dump policy remain deployment work. AWS Nitro
  Enclave isolation helps, but does not replace memory hygiene.

### 2.6 Algorithm Agility & Downgrade Prevention (SEC-06)
- **Problem**: Downgrade attacks or ignoring critical headers could bypass verification constraints.
- **Current state**: The verifier validates the protected `alg`, rejects
  unprotected `alg` declarations, and checks the content type. Unknown critical
  (`crit`) header handling remains follow-up work.

### 2.7 Merkle Tree Duplicate Node Protection (SEC-15)
- **Problem**: The current Merkle Tree implementation duplicates odd nodes (`hashing.rs`), replicating the Bitcoin CVE-2012-2459 vulnerability. If inclusion proofs are introduced later, this creates collision vectors.
- **Mitigation**: Promote the odd node directly up the tree level instead of duplicating.

### 2.8 Model hashing (SEC-16)
- **Problem**: A model file can be replaced after the chat demo computes its startup
  identity, unless the deployment protects the file.
- **Current state**: The metadata-only cache was removed. The chat demo hashes the
  configured file during runtime initialization; the Nitro reference image relies
  on PCR0 covering the model and proxy image. A local process should treat the model
  path as immutable after startup.

### 2.9 Trusted Roots Validation Loop (SEC-17)
- **Problem**: Loop over `trusted_roots` breaks on the first validating root, leaving defense-in-depth security entirely up to the caller to maintain a clean root set.
- **Mitigation**: Sanitize or validate all root CA certificate properties beforehand.

---

## 3. Workspace Panic Safety Scan

A static analysis scan was run across the workspace crates to identify potential panic entry points (`unwrap` and `expect`).

- **`veriai-core`**: 10 matches found. All instances are safe usages of `.unwrap_or_default()`, `.unwrap_or(...)`, or acquiring thread locks (`.lock().unwrap()`).
- **`veriai-attestation`**: **0 unwraps** inside real drivers.
- **`veriai-types`**: **0 unwraps** inside public types.

**Panic safety statement**: No panic path was found in normal untrusted receipt parsing. The mock provider still uses an `expect` for repository-owned certificate fixtures; it is not used by the real-hardware backend.

---

## 4. Security regression tests

The workspace covers malformed and oversized receipts, invalid signatures,
certificate validity and CA constraints, root-first AWS chain ordering, mixed
root pinning attacks, timestamp checks, single-host multi-instance replay,
one-time challenges, nonce generation and required-nonce policy, unknown
critical headers, payload tampering, PCR0, key independence/exhaustion, and
REPORTDATA binding. Real Nitro deployment remains an external test.
