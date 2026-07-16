# Dependency security exceptions

This file records supply-chain findings that cannot currently be removed without
replacing an upstream hardware integration. Exceptions are not vulnerability
waivers: known exploitable vulnerabilities remain release blockers.

## `serde_cbor` 0.11.2 / RUSTSEC-2021-0127

- **Scope:** Transitive dependency of the optional
  `aws-nitro-enclaves-nsm-api` real-hardware feature only.
- **Finding:** The crate is unmaintained. The advisory does not describe a known
  vulnerability.
- **Why retained:** AWS's current NSM API crate still depends on `serde_cbor`
  0.11. Replacing or privately forking the official NSM transport would expand
  the trusted hardware boundary and would require validation on real Nitro
  hardware, which is not available in this repository's local test environment.
- **Compensating controls:** Attestation documents and receipts have strict size
  limits before decoding; the repository's security CI keeps the advisory
  visible instead of suppressing it.
- **Exit condition:** Move to an AWS NSM release that removes `serde_cbor`, or
  adopt a reviewed replacement after real-hardware compatibility testing.
- **Review deadline:** 2026-10-16, and at every production release before then.

## Cargo Vet baseline

The current `supply-chain/config.toml` exemptions are a bootstrap trust baseline,
not proof that repository maintainers audited every dependency. `cargo vet
--locked` prevents dependency changes from silently exceeding that baseline.
Replace exemptions with imported or first-party audits over time; do not generate
blanket audits merely to reduce the exemption count.
