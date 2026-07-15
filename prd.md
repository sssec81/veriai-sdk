**Version:** 10.3 (draft)

**Date:** July 13, 2026

**Status:** Historical planning notes. This file is not the source of truth for
current behavior; use the README, `docs/SPEC.md`, and the code instead.

---

## Table of Contents

1. Executive Summary
2. Competitive Landscape
3. Target Audience & User Personas
4. Critical Protocol Decisions
5. Scope Boundary (v1)
6. Project Structure & Build Safety
7. Core Features & Requirements
8. Technical Architecture & Verification
9. Business Model & Go-to-Market
10. Risks & Mitigations
11. Scorecard
12. Immediate Next Steps

---

## 1. Executive Summary

### 1.1 Vision

Build a small, vendor-neutral attestation library for AI inference. The library records the model, inputs, outputs, and hardware evidence in a signed receipt.

### 1.2 Mission

Build an open-source Rust SDK that generates signed receipts binding model identity, AWS Nitro attestation, and input/output hashes. The SDK can run as a library or as a proxy inside an enclave.

**Security model, stated plainly:** library mode signs and hashes the bytes it is given. The local proxy example owns the runtime call, but only the AWS Nitro deployment places that proxy and model inside a measured enclave image. Claims about hardware-backed inference apply only after that deployment is built and its PCR0 is checked.

### 1.3 Core Problem Statement

AI inference is a black box. High‑stakes use cases (finance, healthcare, autonomous agents) need cryptographic evidence, not vendor assurances. VeriAI provides the audit trail.

### 1.4 Why This Matters Now

- **EU AI Act** creates regulatory pressure for auditable AI systems.
- **EQTY Lab** and **Eigen Labs' EigenCloud/EigenAI** (verifiable, TEE-backed inference with cryptoeconomic security via restaking) demonstrate real commercial and investor interest in provable inference — this is the correct comparable, and it's a live product, not a rumor.
- Neutral, portable, open‑source approach differentiates VeriAI from both of the above, which are proprietary platforms.

> **Correction from v10.2:** the earlier draft cited a "$643M EigenAI acquisition" as market validation. That figure is real but belongs to a different company — Nebius's May 2026 acquisition of *Eigen AI*, an unrelated MIT HAN Lab spinout that does inference-speed/quantization optimization, not attestation or verifiability. It has no bearing on this category and has been removed as a proof point. The actual competitor in this space, Eigen Labs' EigenCloud/EigenAI product, is cited above instead — it's a weaker soundbite than a nine-figure acquisition, so the market-validation argument here is now honestly "there is a live, funded competitor," not "the category was just validated by an exit."
> 

---

## 2. Competitive Landscape

| Player | Approach | Our Opening |
| --- | --- | --- |
| **Eigen Labs (EigenCloud / EigenAI)** | Deterministic re‑execution + restaking / cryptoeconomic slashing | Neutral, portable; no staking or token dependency; smaller codebase, easier to audit |
| **OpenPCC** | Generic TEE attestation *(unverified — confirm exact positioning before citing in external materials)* | AI‑specialized: model hashing, per‑inference receipts |
| **EQTY Lab** | Proprietary enterprise platform | Open‑source library, not a walled garden |
| **io.net** | Proprietary to their network | Portable across any DePIN or cloud |
| **IETF AIR draft** | Fragmented proposals *(unverified — confirm current draft status before citing)* | Track it, but position as **"practical attestation"** not reference implementation |

---

## 3. Target Audience & User Personas

- **Persona A – DePIN / Cloud AI Platform CTO** – Integrates SDK into node client to prove model fidelity.
- **Persona B – Enterprise Compliance Officer** – Needs audit trails for EU AI Act; buys hosted dashboard (v2).
- **Persona C – AI Agent Developer** – Needs verifiable decision traces.

---

## 4. Critical Protocol Decisions

All decisions are verified against the official AWS Nitro Enclaves Attestation Document specification.

| # | Decision | Specification |
| --- | --- | --- |
| 1 | **Attestation signing** | AWS Nitro uses **ECDSA P‑384 with SHA‑384**. Receipt signing (COSE_Sign1) uses enclave‑generated **Ed25519**. |
| 2 | **REPORTDATA** | `SHA‑512(0x01 ‖ "VeriAI‑KeyBind‑v1" ‖ Ed25519_PubKey_32bytes)` → 64‑byte `user_data`. |
| 3 | **PCR0 validation** | Mandatory PCR0 (48‑byte SHA‑384 hash of the EIF). Verifier MUST check `PCR0 == expected_pcr0`. |
| 4 | **Nonce lifecycle** | **Per‑inference** call to `/dev/nsm` with client nonce; no caching of attestation docs. |
| 5 | **Reboot detection** | No standalone `boot_id`. Use **identity fingerprint**: `(PCR0, PCR3, PCR4, module_id, cert_chain_fingerprint)`. Store **SHA‑256 of concatenated fingerprint** for compact state. **Rust SDK only — see #14.** |
| 6 | **Attestation doc timestamp** | `uint .size 8` (milliseconds since UNIX epoch). Verifier checks both claim 6007 (seconds) and doc timestamp (ms) within ±5 min. |
| 7 | **Security boundary** | SDK is a library by default. **Full I/O-fabrication protection requires proxy deployment** inside the enclave, and the proxy binary **must** be part of PCR0. Library mode alone does not prevent a dishonest operator from fabricating inputs/outputs — see Section 1.2. |
| 8 | **Model hash caching** | No metadata-only cache is used. The chat demo computes the model hash during runtime initialization; Nitro PCR0 must protect the model and image after startup. |
| 9 | **WASM size** | Current full-chain build is 308 KB gzipped and CI enforces a 350 KB ceiling. The original 200 KB target remains open; reducing dependencies or using a pinned-leaf mode are possible follow-ups. |
| 10 | **Build‑time guard** | `mock‑hardware` and `real‑hardware` mutually exclusive. `compile_error!` on release with mock (except `test‑mode`). |
| 11 | **Mock signing** | Mock docs signed by test private key; verifier accepts override only in test builds. |
| 12 | **COSE_Sign1 headers** | `alg`: `EdDSA` (-8). `kid`: omitted. `content‑type`: `application/cwt` (SHOULD be present). |
| 13 | **Receipt wire format** | Raw COSE_Sign1 bytes. Transport encoding is caller's responsibility. |
| 14 | **WASM replay protection gap** | The WASM verifier is stateless and does not track sequence numbers or identity fingerprints (per #5). It therefore cannot detect enclave reboot/replay across calls. This must be documented as an explicit limitation everywhere the WASM verifier is offered — not just implied by "stateless." Browser/DePIN integrators relying on WASM-only verification get weaker guarantees than Rust-SDK integrators. |
| 15 | **WASM budget contingency** | The current full-chain build is above the 200 KB target. Decide later whether to reduce dependencies or offer an explicitly weaker pinned-leaf mode. |

---

## 5. Scope Boundary (v1)

### In Scope

- TEE‑based attestation (AWS Nitro only)
- Full local simulation via `mock‑nsm`
- Merkle‑tree model hashing over raw file bytes; the chat demo computes the model identity during runtime initialization
- Canonical JSON serialization for the chat request and SHA-256 hashing of the exact output bytes
- COSE_Sign1 / CWT receipt generation (claims 6000–6007, 6011, 6012)
- PCR0 validation (48‑byte SHA‑384)
- Rust verification SDK (stateful: sequence + identity fingerprint tracking)
- WASM verification module (stateless, currently 308 KB gzipped; 200 KB remains a planning target)
- CLI tool and Docker/Nitro reference deployment
- Build‑time safety guard
- Open‑source (Apache 2.0)
- Local proxy example and an AWS Nitro deployment reference in `examples/01-chat-demo/` and `deploy/nitro/`

### Out of Scope (v1)

- Deterministic dual‑node re‑execution
- SCITT / transparency logs
- Custom registry services
- Intel TDX / AMD SEV‑SNP
- Hosted Policy Engine / Dashboard (v2)
- Claims 6008–6010 (reserved; claims 6011 and 6012 are used)
- Sequence/reboot checks in WASM verifier (documented limitation, not deferred silently)
- Multi‑file model formats (only single‑file Safetensors or raw binary)
- Full X.509 chain validation in WASM if budget contingency (#15) is triggered

---

## 6. Project Structure & Build Safety

```
veriai-sdk/
├── Cargo.toml
│   ├── [features]
│   │   ├── mock-hardware   # default for dev
│   │   ├── real-hardware   # for release (mutually exclusive)
│   │   └── test-mode       # bypasses compile_error for tests
├── crates/
│   ├── veriai-types/
│   ├── veriai-core/
│   ├── veriai-attestation/
│   ├── veriai-runtime/
│   ├── veriai-cli/
│   ├── veriai-wasm/
│   └── verifier-service/
├── tests/fixtures/
│   ├── mock-aws-root.pem
│   ├── mock-aws-root.key.pem
│   └── mock certificate fixtures
├── examples/
│   └── 01-chat-demo/
├── deploy/nitro/
└── .github/workflows/
    └── ci.yml
```

### Build‑Time Safety Guard

```rust
// crates/*/src/lib.rs
#[cfg(all(feature = "mock-hardware", feature = "real-hardware"))]
compile_error!("Features 'mock-hardware' and 'real-hardware' are mutually exclusive.");

#[cfg(all(feature = "mock-hardware", not(debug_assertions), not(feature = "test-mode")))]
compile_error!("Feature 'mock-hardware' is not allowed in release builds. Use --features real-hardware or enable test-mode for test binaries.");
```

---

## 7. Core Features & Requirements

### 7.1 CWT Claim Set (CDDL – v1)

```
veriai-claims = {
    6000 => bstr .size 32,   ; model-hash (Merkle root, SHA-256)
    6001 => bstr .size 32,   ; input-hash (SHA-256)
    6002 => bstr .size 32,   ; output-hash (SHA-256)
    6003 => bstr .size 32,   ; client-nonce (echoed, also in Nitro 'nonce')
    6004 => uint,            ; sequence-num (resets on reboot)
    6005 => bstr,            ; attestation-report (raw CBOR)
    6006 => uint,            ; attestation-type (3 = Nitro)
    6007 => int,             ; attestation-timestamp (Unix seconds, ±5min tolerance)
    6011 => text,            ; sdk-version (e.g., "veriai-sdk/1.0.0")
    6012 => bstr .size 32,   ; enclave-pubkey (Ed25519)
}
```

*(Claims 6008–6010 are reserved and MUST NOT appear.)*

### 7.2 Mandatory Features

| Feature | Implementation |
| --- | --- |
| NSM Module (split) | `nsm/schema.rs` (pure CBOR), `nsm/mock.rs`, `nsm/real.rs`. Includes P‑384 signature verification. |
| Schema Validation | `tests/schema.rs` – compares mock CBOR against real Nitro fixture. |
| PCR0 Validation | Verifier receives `expected_pcr0` (48 bytes). Extracts PCR0 from attestation doc; rejects on mismatch. |
| Merkle Tree Hasher | `crates/veriai-core/src/hashing.rs` – 4MB chunks, raw file bytes, no metadata-only cache. The chat demo hashes once during runtime initialization. |
| Input/Output Hashing | Canonical JSON request bytes and SHA-256 of the exact completion output. |
| COSE_Sign1 / CWT Builder | `crates/veriai-core/src/receipt.rs` – claims 6000–6007, 6011, 6012. New receipts protect `application/cwt`. |
| Receipt Verification SDK | `crates/veriai-core/src/verify.rs` – verification flow, stateful sequence, and identity fingerprint tracking. |
| Error Taxonomy | `crates/veriai-types/src/error.rs` – `VerifyError` and attestation errors. |
| WASM Verification Module | `crates/veriai-wasm/` – verifier only, no NSM. Stateless; replay-detection gap documented. JS API: `verifyReceipt(...)`. |
| CLI Tool | `crates/veriai-cli/` – `generate`, `inspect`, and `verify` with optional session state. |
| Docker/Nitro Reference | `Dockerfile` for the verifier service and `deploy/nitro/` for the measured chat proxy. |
| CI | GitHub Actions: format, Clippy, workspace tests, WASM build/size check, and real-hardware release compilation. |
| Proxy Reference Example | `examples/01-chat-demo/` locally and `deploy/nitro/` for the measured AWS deployment. |

---

## 8. Technical Architecture & Verification

### 8.1 Core Flow (Proxy Deployment)

```
CLIENT (Verifier)
  → 1. Generates 32‑byte nonce + chooses expected model (by PCR0 + model hash)
  → 2. Computes expected input/output hashes (canonical)
  → 3. Sends inference request + nonce to proxy endpoint
  → 4. Proxy (inside enclave):
         a. Intercepts actual model file (mmap), computes hash
         b. Intercepts actual input bytes, computes hash
         c. Runs inference, captures output bytes, computes hash
         d. Calls NSM with nonce → attestation doc
         e. Builds receipt (COSE_Sign1) with all claims
  → 5. Returns receipt (raw bytes) to client
  → 6. Verifier runs 6‑step verification
```

*Library mode follows the same receipt format but steps 4a–4c are performed by the operator's own code calling into the SDK, not by an intercepting proxy — meaning a dishonest operator can pass fabricated bytes into a, b, c. Only proxy mode gives the guarantee described in Section 1.1.*

### 8.2 The 6‑Step Verification Chain (v1)

1. **Signature Verification** – Verify COSE_Sign1 using `enclave-pubkey` (6012). *Failure → `InvalidCoseSignature`.*
2. **Attestation Validation** – Verify attestation report (6005) against the **root certificate** (AWS CABundle or mock override). Validate the doc's *own* timestamp (`uint .size 8`, milliseconds since UNIX epoch) against current time (±5 min). *Failure → `InvalidAttestationDocument` or `AttestationDocTimestampMismatch`.*
3. **PCR0 Validation** – Extract PCR0 (48‑byte SHA‑384) and compare to `expected_pcr0`. *Failure → `PcrMismatch`.*
4. **Pubkey Binding** – Extract `public_key` from attestation doc (1‑1024 bytes) and compare to claim 6012. *Failure → `PubkeyBindingMismatch`.*
5. **REPORTDATA Binding** – Compute `SHA-512(0x01 || "VeriAI-KeyBind-v1" || claim_6012)` → 64 bytes and compare to attestation doc's `user_data` (0‑1024 bytes). *Failure → `ReportDataMismatch`.*
6. **Payload Checks**:
    - `client‑nonce` (6003) matches attestation doc's `nonce`. *Failure → `NonceMismatch`.*
    - claim 6007 within ±5 min (and consistent with doc timestamp). *Failure → `TimestampSkewExceeded`.*
    - `model‑hash`, `input‑hash`, `output‑hash` match expected. *Failure → respective hash mismatch.*
    - **(Stateful only — Rust SDK, not WASM):** `sequence‑num` (6004) is monotonic within the same **identity fingerprint** (hash of PCR0, PCR3, PCR4, module_id, cert fingerprint). If identity changes, sequence reset is allowed. *Failure → `SequenceNumberOutOfOrder` or `EnclaveIdentityChanged`.*

### 8.3 Error Taxonomy (`crates/veriai-types/src/error.rs`)

```rust
pub enum VerifyError {
    InvalidCoseSignature,
    InvalidAttestationDocument,
    AttestationDocTimestampMismatch,
    PcrMismatch,
    PubkeyBindingMismatch,
    ReportDataMismatch,
    TimestampSkewExceeded,
    ModelHashMismatch,
    InputHashMismatch,
    OutputHashMismatch,
    NonceMismatch,
    SequenceNumberOutOfOrder,
    EnclaveIdentityChanged,
    MalformedReceipt,
}
```

### 8.4 Identity Fingerprint Hashing

The implementation lives in `crates/veriai-core/src/verify.rs`:

```rust
fn compute_identity_fingerprint(doc: &AttestationDoc) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&doc.pcrs[0]);      // PCR0, 48 bytes
    hasher.update(&doc.pcrs[3]);      // PCR3
    hasher.update(&doc.pcrs[4]);      // PCR4
    hasher.update(doc.module_id.as_bytes());
    hasher.update(&cert_fingerprint(doc.certificate_chain));
    hasher.finalize().into()
}
```

Store this hash in the session state instead of raw tuple. Rust SDK only — not available in WASM (Decision #14).

### 8.5 Timestamp Handling

- Attestation doc timestamp: **64‑bit unsigned integer, milliseconds since UNIX epoch**.
- Claim 6007: **integer seconds** (UNIX time).
- Verifier converts doc timestamp to seconds (`ms / 1000`) and ensures both are within ±5 minutes of system clock.

### 8.6 WASM JS API

```jsx
const result = verify_receipt(
    receipt_bytes,        // Uint8Array
    expected_model_hash,  // Uint8Array(32)
    expected_input_hash,  // Uint8Array(32)
    expected_output_hash, // Uint8Array(32)
    expected_nonce,       // Uint8Array(32)
    expected_pcr0         // Uint8Array(48)
);
// Returns { valid: bool, error?: string }
// Note: no replay/reboot protection in this mode — see Decision #14.
```

---

## 9. Business Model & Go-to-Market

**Framing:** this is a near-zero-cost, high-optionality bet on an open-source reference implementation, not a validated business. Treat the numbers below as a plan to reach the first real signal (a design partner willing to pay for integration help), not as revenue projections to build a runway around.

### 9.1 Revenue Streams

| Stream | Model |
| --- | --- |
| Open source SDK | Free, Apache 2.0 |
| Consulting / Integration | Paid engagements ($5‑15K each). First revenue stream. |
| Hosted Policy Engine + Dashboard | **v2** – after market validation and ≥2 design partners. |
| Enterprise License | Bundled hosted service + SLA + liability (post‑v1). |

### 9.2 Revenue Timeline (Honest)

- Months 1–6: $0 (build)
- Months 6–12: $0 (design partners, free integrations)
- Months 12–18: $30‑60K from consulting *(assumes at least one design partner converts — not guaranteed by the outreach plan below)*
- Months 18–24: Evaluate hosted service demand

### 9.3 Go‑to‑Market Plan

| Phase | Timeline | Deliverable | Cost |
| --- | --- | --- | --- |
| Spec Finalisation | Days 1–5 | Real Nitro experiment, PCR policy, proxy decision. | <$2 |
| Local Build + CI | Weeks 1–10 | Full SDK + WASM + CLI + tests + CI. | $0 |
| Real Nitro Integration | Weeks 10–16 | Deploy to Nitro (AWS credits or ~$5). | $0 / ~$5 |
| Design Partners Outreach | Week 12 | Contact 10‑15 DePIN/cloud CTOs. Realistic: 1‑2 responses. | $0 |
| Launch (Open Source) | Week 20 | Public release, WASM on npm, blog posts. | $0 |
| Consulting Gigs | Weeks 20‑24 | Paid integrations for early adopters. | $0 |

---

## 10. Risks & Mitigations

| Risk | Mitigation |
| --- | --- |
| **Attestation uses P‑384, not Ed25519** | ✅ Separate keys: P‑384 for attestation validation, Ed25519 for receipt signing. |
| **No PCR validation** | ✅ Mandatory PCR0 check (48‑byte SHA‑384). |
| **No boot_id field** | ✅ Identity fingerprint (PCR0, PCR3, PCR4, module_id, cert chain) hashed — Rust SDK only. |
| **Nonce lifecycle ambiguous** | ✅ Per‑inference attestation; no caching. |
| **Attestation doc timestamp not checked** | ✅ Validate doc timestamp (ms) and claim 6007 (seconds). |
| **I/O fabrication by operator** | ⚠️ Only addressed by the measured proxy deployment; library mode does not close this gap. |
| **Model replacement after startup** | ⚠️ Local processes must protect the configured model file. Nitro deployment relies on PCR0 covering the model and proxy image; the chat demo does not rehash the file for every request. |
| **WASM size >200KB** | ⚠️ Current build is 308 KB gzipped under a 350 KB CI ceiling; the original 200 KB target remains open. |
| **X.509 cert chain in WASM** | Budget 2 weeks; use well‑audited crates; check dependencies early; contingency plan defined above if budget is missed. |
| **WASM has no replay/reboot detection** | ⚠️ New: documented as a stated limitation (Decision #14), not silently deferred. Integrators choosing WASM-only verification should know they're accepting weaker guarantees. |
| **Market-validation citation was factually wrong (v10.2)** | ✅ Corrected in Section 1.4 / 2 — replaced with the actual relevant competitor (Eigen Labs' EigenCloud/EigenAI) instead of an unrelated acquisition. |

---

## 11. Scorecard

| Factor | Score | Notes |
| --- | --- | --- |
| Product innovation | 7/10 | Neutral positioning, proxy deployment model. |
| Market clarity | 5/10 | Consulting first; enterprise later; no design partner commitments yet. |
| Founder fit | 8/10 | Strong Rust + security. |
| Defensibility | 4/10 | Apache 2.0; proxy + AI‑specialised logic provide some moat but a well-funded competitor (Eigen Labs) could replicate quickly. |
| Capital efficiency | 9/10 | Near‑zero cash burn. |
| Protocol correctness | **9/10** | Nitro-specific claims check out against known spec; downgraded one point pending independent review of the IETF AIR draft and OpenPCC positioning claims, which are unverified. |
| **Total** | **42/50** | **Credible and buildable as an open-source bet. Business case is a low-cost option on future revenue, not a validated market — proceed on that basis.** |

---

## 12. Historical next steps

The following list is retained as planning history. It is not a current
implementation checklist; verify status against the repository before using it.

1. **Real Nitro experiment** – capture an attestation doc, parse it, save as `real-nitro-attestation.cbor`, confirm PCR0 size (48 bytes), timestamp format (uint64 ms), and certificate chain. (Day 1)
2. **Write `docs/SPEC.md`** – incorporate the final CDDL, 6‑step flow, identity fingerprint hashing, timestamp conversion, and the library-mode-vs-proxy-mode security distinction (Section 1.2) up front. (Day 2)
3. **`cargo init veriai-sdk --lib`** – historical repository bootstrap step; the current workspace is already split into crates. (Day 2)
4. **Generate mock certificates** – `tests/fixtures/mock-aws-root.pem` & key. (Day 3)
5. **Write `src/nsm/schema.rs`** – historical single-crate path; the current implementation lives under `crates/`. (Week 1)
6. **Set up CI** – including WASM gzipped size check. (Day 3)
7. **Evaluate WASM deps** – run `cargo tree`, ensure no bloated dependencies, and make the pinned-leaf-cert-vs-full-chain call (Decision #15) by end of Week 1 rather than discovering it late. (Week 1)
8. **Build the proxy reference example as a working demo**, not a stub — this is the only deployment mode that delivers the core value proposition, so it needs to be provable early. (Weeks 2–4)
9. **Before external use, verify the OpenPCC and IETF AIR draft claims in Section 2** — these are currently unverified and shouldn't be cited in outward-facing materials until confirmed.

---

**Status: technically ready to build. Business case is honestly thin — proceed as a low-cost bet on becoming a reference implementation, not as a validated go-to-market.**
