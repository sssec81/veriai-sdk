# VeriAI Technical Specification (v1.0)

## 1. Security Models & The Golden Rule

VeriAI supports two distinct deployment modes. The core value proposition of VeriAI is verifiable inference, but the security guarantee differs materially between these modes:

### 1.1 Library Mode (Default)
In Library Mode, the SDK is imported by the host application. The host calls the SDK to hash inputs/outputs and retrieve attestation documents.
* **Guarantee**: Provides cryptographic signatures of what the SDK was told was run.
* **Threat Model Gap**: A dishonest operator can run a different model or feed fake inputs/outputs to the SDK while running something else entirely. Library mode **does not** prevent operator I/O fabrication.

### 1.2 Proxy Mode (Secure)
In Proxy Mode, VeriAI runs as an intercepting proxy inside the secure AWS Nitro Enclave. All inference requests must pass through this proxy.
* **Guarantee**: The proxy itself intercepts the model file (mmap), calculates the hash, catches the inputs, forwards them to the model, catches the outputs, and generates the attestation document with binding report data.
* **Security Guard**: Because the proxy binary is included in the enclave's PCR0, the client can verify that the proxy is indeed running and managing the I/O. This is the **only** mode that provides full defense against operator fabrication.

---

## 2. CWT Claim Set

The receipt is a `COSE_Sign1` structure enclosing a CBOR Web Token (CWT) with the following claims:

| Claim Key | CDDL Type | Name | Description |
|---|---|---|---|
| **6000** | `bstr .size 32` | `model-hash` | SHA-256 Merkle root of the model file |
| **6001** | `bstr .size 32` | `input-hash` | SHA-256 hash of the canonical input bytes |
| **6002** | `bstr .size 32` | `output-hash` | SHA-256 hash of the canonical output bytes |
| **6003** | `bstr .size 32` | `client-nonce` | Client-provided nonce, echoed back |
| **6004** | `uint` | `sequence-num` | Monotonically increasing sequence number, resets on reboot |
| **6005** | `bstr` | `attestation-report` | Raw CBOR attestation document from `/dev/nsm` |
| **6006** | `uint` | `attestation-type` | Attestation type (value must be `3` for AWS Nitro) |
| **6007** | `int` | `attestation-timestamp` | Unix epoch time in seconds (±5 minutes tolerance) |
| **6011** | `text` | `sdk-version` | SDK version identifier (e.g., `"veriai-sdk/1.0.0"`) |
| **6012** | `bstr .size 32` | `enclave-pubkey` | Public key of the enclave's ephemeral Ed25519 keypair |

> [!WARNING]
> Claims 6008, 6009, and 6010 are reserved. They must not appear in the claim set.

---

## 3. The 6-Step Verification Chain

Verifiers must perform the following validation steps sequentially:

1. **Signature Verification**: Validate the `COSE_Sign1` structure signature using `enclave-pubkey` (6012).
2. **Attestation Validation**: Parse the `attestation-report` (6005) and verify its signature against the root CA certificate (AWS CABundle or mock override). Validate the report's internal timestamp (`uint .size 8` in milliseconds) against the system clock (±5 minutes).
3. **PCR0 Validation**: Extract the PCR0 field from the attestation document and verify that it matches the `expected_pcr0` exactly.
4. **Pubkey Binding**: Verify that the ephemeral public key inside the attestation document match `enclave-pubkey` (6012) exactly.
5. **REPORTDATA Binding**: Ensure the Nitro document's `user_data` (REPORTDATA) matches the expected SHA-512 hash:
   $$\text{REPORTDATA} = \text{SHA-512}(0\text{x}01 \mathbin{\Vert} \text{"VeriAI-KeyBind-v1"} \mathbin{\Vert} \text{Ed25519\_PubKey\_32bytes})$$
6. **Payload Checks**:
   * Verify that `client-nonce` (6003) matches the Nitro document's `nonce`.
   * Verify that `attestation-timestamp` (6007) is within ±5 minutes of the verifier's system clock.
   * Verify that `model-hash`, `input-hash`, and `output-hash` match expectation.
   * **(Rust SDK Stateful Verifier only)**: Compute the identity fingerprint:
     $$\text{IdentityFingerprint} = \text{SHA-256}(\text{PCR0} \mathbin{\Vert} \text{PCR3} \mathbin{\Vert} \text{PCR4} \mathbin{\Vert} \text{module\_id} \mathbin{\Vert} \text{cert\_fingerprint})$$
     Verify that `sequence-num` (6004) increases monotonically for the same fingerprint. Allow reset only if the fingerprint changes.
