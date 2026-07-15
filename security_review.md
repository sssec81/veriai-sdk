# VeriAI security notes

This is a working list of security risks and mitigations in the repository. It is not an independent security audit or a claim that the system is ready for production.

---

## 1. Risk Classification & Threat Matrix

| ID | Title | Severity | Impact | Mitigation Status |
| :--- | :--- | :---: | :--- | :--- |
| **SEC-01** | Missing Certificate Validity Checks | High | Expired leaf or intermediate certs accepted | **Implemented in code** (checks validity period across entire chain) |
| **SEC-02A**| Verifier State Replay (Reset/Scale) | Critical | Sequence bypass on verifier restart or horizontal scaling | **Partially implemented** (atomic file persistence for one process; shared transactional storage remains follow-up) |
| **SEC-02B**| Attestation Receipt Replay | Critical | Valid old receipts accepted forever | **Implemented in code** (maximum receipt age and timestamp checks) |
| **SEC-03** | Enclave Private Key Lifecycle Protection | Critical | Key theft if written to disk or cloned in memory | **Partially implemented** (`SigningKey` zeroization enabled; locked memory and core-dump policy remain deployment work) |
| **SEC-04** | Resource Exhaustion (OOM) via CBOR/COSE | High | Denial of service via malicious large files | **Implemented in code** (receipt and HTTP body limits) |
| **SEC-05** | Replay State File / Symlink Attacks | High | Privilege escalation, file overwrite, or write corruption | **Partially implemented** (metadata cache removed; replay state uses create-new temporary files and atomic replacement) |
| **SEC-06** | Algorithm Agility Attacks | High | Downgrade to `none` or weaker signatures | **Partially implemented** (protected algorithms and content type checked; unknown critical headers remain follow-up) |
| **SEC-07** | Certificate Extension Validation | High | Impersonation using client auth certs | **Implemented in code** (checks `basicConstraints CA:true` on intermediates) |
| **SEC-08** | Root Certificate Pinning Brittleness | High | Service breakdown on AWS root CA rotations | **Follow-up** (support controlled embedded CA fingerprint sets) |
| **SEC-09** | Input Ambiguity in Key Binding | High | Concatenation prefix collision attacks | **Follow-up** (hash structured CBOR arrays instead of concatenation) |
| **SEC-10** | Release Build Mock Mode Drift | High | Shipping mock hardware backend to production | **Implemented in code** (compile-time check outside tests) |
| **SEC-11** | Missing Attestation Freshness Check | Critical | Replaying old valid attestation documents | **Implemented in code** (five-minute clock-skew window) |
| **SEC-12** | Nonce Entropy Validation | High | Low-entropy or predictable nonces enabling replay | **Follow-up** (require nonces from a CSPRNG) |
| **SEC-13** | Memory Leakage & Exposure | Medium | Key leak through core dumps, debugging, or swap | **Follow-up** (use `mlock` and disable core dumps) |
| **SEC-14** | Dependency Supply Chain | Medium | Upstream library security vulnerabilities | **Follow-up** (add cargo audit, deny, and vet to CI) |
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
  2. **Key Usage & EKU**: Verify `BasicConstraints` (checking `CA:true`), `KeyUsage`, and `ExtendedKeyUsage` properties. **[BasicConstraints CA:true Implemented & Verified]**
  3. **CA Bundle Ordering**: Ensure that the chain validation walks the expected ordering (root-first vs leaf-first) as returned by AWS Nitro Enclaves to avoid verification bypasses. **[Documented & Verified leaf-to-root order against AWS specification]**
  4. **Fingerprint Set CA Pinning**: Avoid automated root expansion; verify root certificate fingerprints against an embedded trusted CA set. **[Recommended]**

### 2.3 REPORTDATA Input Ambiguity Protection (SEC-09)
- **Problem**: Concatenating variables `version || domain || key` can result in input ambiguity where different configurations serialize to the identical byte stream.
- **Follow-up**: Change the binding input to a structured encoding before hashing:
  ```rust
  // SHA-512(CBOR([version, domain, pubkey]))
  ```

### 2.4 State Replay Protection & distributed Enclaves (SEC-02A, SEC-02B)
- **Problem**: A verifier restart or multiple verifier instances can lose or split sequence state.
- **Mitigations**:
  1. **Single-process persistence**: `STATE_FILE_PATH` writes sequence state atomically and restores it on startup. Verification is rolled back if persistence fails.
  2. **Distributed Sequence Store**: Use a transactional shared database before horizontal scaling.
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

The workspace currently covers malformed and oversized receipts, invalid
signatures, certificate validity and CA constraints, timestamp checks, replay,
payload tampering, PCR0, and REPORTDATA binding. The remaining test work is
primarily for multi-process replay storage, unknown critical headers, and the
real Nitro deployment path.
