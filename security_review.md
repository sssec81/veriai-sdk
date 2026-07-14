# VeriAI Internal Security Threat Review

This document registers a professional threat assessment and code-level audit of the VeriAI workspace. It incorporates security review critiques, classifies risk severity, and maps concrete mitigations.

---

## 1. Risk Classification & Threat Matrix

| ID | Title | Severity | Impact | Mitigation Status |
| :--- | :--- | :---: | :--- | :--- |
| **SEC-01** | Missing Certificate Validity Checks | 🟠 High | Expired leaf or intermediate certs accepted | **Recommended** (verify validity across entire chain) |
| **SEC-02A**| Verifier State Replay (Reset/Scale) | 🔴 Critical | Sequence bypass on verifier restart or horizontal scaling | **Recommended** (persistent Redis or stateless nonces) |
| **SEC-02B**| Attestation Receipt Replay | 🔴 Critical | Valid old receipts accepted forever | **Recommended** (enforce MAX_RECEIPT_AGE thresholds) |
| **SEC-03** | Enclave Private Key Lifecycle Protection | 🔴 Critical | Key theft if written to disk or cloned in memory | **Recommended** (use `Zeroizing` and avoid cloning keys) |
| **SEC-04** | Resource Exhaustion (OOM) via CBOR/COSE | 🟠 High | Denial of Service (DoS) via malicious large files | **Recommended** (enforce configurable size limits, return `Err`) |
| **SEC-05** | Cache Poisoning / Symlink Attacks | 🟠 High | Privilege escalation / file overwrite / write corruption | **Recommended** (atomic writes, strict permissions, no-follow) |
| **SEC-06** | Algorithm Agility Attacks | 🟠 High | Downgrade to `none` or weaker sigs / ignored headers | **Recommended** (check protected header, reject unknown crit) |
| **SEC-07** | Certificate Extension Validation | 🟠 High | Impersonation using client auth certs | **Recommended** (validate EKU, SAN, and BasicConstraints) |
| **SEC-08** | Root Certificate Pinning Brittleness | 🟠 High | Service breakdown on AWS Root CA rotations | **Recommended** (support controlled embedded CA fingerprint sets) |
| **SEC-09** | Input Ambiguity in Key Binding | 🟠 High | Concatenation prefix collision attacks | **Recommended** (hash structured CBOR arrays instead of concat) |
| **SEC-10** | Release Build Mock Mode Drift | 🟠 High | Shipping mock hardware backend to production | **Recommended** (compile_error check outside of tests) |
| **SEC-11** | Missing Attestation Freshness Check | 🔴 Critical | Replaying old valid attestation documents | **Recommended** (enforce 5-minute maximum clock skew window) |
| **SEC-12** | Nonce Entropy Validation | 🟠 High | Low-entropy/predictable nonces enabling replay | **Recommended** (enforce minimum 128-bit CSPRNG nonces) |
| **SEC-13** | Memory Leakage & Exposure | 🟡 Medium | Key leak through core dumps, debugging, or swap | **Recommended** (use `mlock` and disable core dumps) |
| **SEC-14** | Dependency Supply Chain | 🟡 Medium | Upstream library security vulnerabilities | **Recommended** (integrate cargo audit, deny, and vet in CI) |
| **SEC-15** | Merkle Tree Odd-Node Duplication | 🟡 Medium | Hash collision vulnerabilities during inclusion proofs | **Recommended** (promote rather than duplicate odd nodes) |
| **SEC-16** | Model Hash Cache Metadata Trust | 🟡 Medium | Swapped-out model files via touched file metadata | **Recommended** (validate content hash, not just mtime/size) |
| **SEC-17** | Weak Trusted Roots Verification Path | 🟢 Low | Defense-in-depth bypass if mixed roots list provided | **Recommended** (sanitize or require validation of all certs) |

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
  1. **Temporal Chain Check**: Validate the `validity` window (NotBefore / NotAfter) on the leaf cert and all intermediate certs in the chain against system clock.
  2. **Key Usage & EKU**: Verify `BasicConstraints` (checking `CA:true`), `KeyUsage`, and `ExtendedKeyUsage` properties.
  3. **CA Bundle Ordering**: Ensure that the chain validation walks the expected ordering (root-first vs leaf-first) as returned by AWS Nitro Enclaves to avoid verification bypasses.
  4. **Fingerprint Set CA Pinning**: Avoid automated root expansion; verify root certificate fingerprints against an embedded trusted CA set.

### 2.3 REPORTDATA Input Ambiguity Protection (SEC-09)
- **Problem**: Concatenating variables `version || domain || key` can result in input ambiguity where different configurations serialize to the identical byte stream.
- **Mitigation**: CBOR encode the properties as a structured array before hashing:
  ```rust
  // SHA-512(CBOR([version, domain, pubkey]))
  ```

### 2.4 State Replay Protection & distributed Enclaves (SEC-02A, SEC-02B)
- **Problem**: Mutex state tracks sequence numbers in-memory. If the verifier restarts or is scaled horizontally, sequence records reset to zero. Furthermore, old receipts are valid forever.
- **Mitigations**:
  1. **Distributed Sequence Store**: Track sequence numbers using Redis or DynamoDB.
  2. **Receipt Expiration Check**: Enforce maximum allowed receipt age (e.g. `MAX_RECEIPT_AGE = 5 minutes` from generation timestamp).

### 2.5 Private Key Lifecycle (SEC-03, SEC-13)
- **Problem**: Ephemeral signing keys could leak via core dumps, memory pages, or cloning.
- **Mitigation**:
  - Enforce ownership and wrap keys in `Zeroizing` wrappers to scrub memory pages on `drop`.
  - Pin pages with `mlock` and disable core dumps. *Note: AWS Nitro Enclave isolation helps, but memory hygiene remains essential.*

### 2.6 Algorithm Agility & Downgrade Prevention (SEC-06)
- **Problem**: Downgrade attacks or ignoring critical headers could bypass verification constraints.
- **Mitigation**: Validate the `alg` identifier in protected headers, reject unprotected `alg` declarations, and fail on any unknown critical (`crit`) header elements.

### 2.7 Merkle Tree Duplicate Node Protection (SEC-15)
- **Problem**: The current Merkle Tree implementation duplicates odd nodes (`hashing.rs`), replicating the Bitcoin CVE-2012-2459 vulnerability. If inclusion proofs are introduced later, this creates collision vectors.
- **Mitigation**: Promote the odd node directly up the tree level instead of duplicating.

### 2.8 Cache Hijack Protection (SEC-16)
- **Problem**: Model-hash caching relies on file `mtime` and size, allowing attackers to touch file metadata and swap model files without cache invalidation.
- **Mitigation**: Add a content hashing validation step or explicitly restrict cache scope.

### 2.9 Trusted Roots Validation Loop (SEC-17)
- **Problem**: Loop over `trusted_roots` breaks on the first validating root, leaving defense-in-depth security entirely up to the caller to maintain a clean root set.
- **Mitigation**: Sanitize or validate all root CA certificate properties beforehand.

---

## 3. Workspace Panic Safety Scan

A static analysis scan was run across the workspace crates to identify potential panic entry points (`unwrap` and `expect`).

- **`veriai-core`**: 10 matches found. All instances are safe usages of `.unwrap_or_default()`, `.unwrap_or(...)`, or acquiring thread locks (`.lock().unwrap()`).
- **`veriai-attestation`**: **0 unwraps** inside real drivers.
- **`veriai-types`**: **0 unwraps** inside public types.

**Panic safety statement**: There are no identified panic paths reachable from normal untrusted input parsing. (Possibilities of poison panics on `.lock().unwrap()` exist only if other threads panic while holding a state mutex).

---

## 4. Security Regression Test Suite

To transition this security review to a verified audit standard, the following test suites must be configured in `tests/`:

1. **Malformed Receipt Suite**: Tests asserting error returns on truncated payload byte vectors, malformed CBOR objects, and size limit breaches.
2. **Chain Validity Suite**: Tests verifying rejection of expired intermediate/leaf certs and algorithm swaps.
3. **Replay Validation Suite**: Tests evaluating horizontal replay attacks and restart resets.
4. **Binding Integrations**: Asserting rejection of tampered `REPORTDATA` and incorrect `PCR0` measurements.

