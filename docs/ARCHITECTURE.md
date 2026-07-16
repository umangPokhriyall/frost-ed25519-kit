# frost-ed25519-kit — Architecture

This document describes the architecture of `frost-ed25519-kit`, including its crate boundaries, module responsibilities, trust boundaries, and major design decisions. It complements `THREAT-MODEL.md`.

---

## 1. The sans-IO boundary

`frost-core` is **pure functions and explicit state machines**. There is no I/O on
the trust path: no `tokio`, `reqwest`, `diesel`, Postgres, or `solana-*` anywhere in
the crate, and there never will be. Keygen, signing, aggregation, verification, and
the DKG rounds are all `(inputs) -> Result<outputs, Error>`; the caller drives the
protocol and owns **all** transport, scheduling, and persistence.

If a feature requires I/O inside `frost-core`, it belongs outside the library boundary.

---

## 2. Module map and the shipped graph

Core modules (`frost-core/src/`):

| module        | responsibility                                                                                                                                                                                      |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `group`       | validated, constant-time scalar/point/identifier layer — the only place raw `curve25519-dalek` types are touched; rejects non-canonical scalars, non-prime-order points, zero/duplicate identifiers |
| `secret`      | zeroizing secret types (`SigningShare`, `SigningNonces`, `SecretPolynomial`); single-use nonces by type                                                                                             |
| `vss`         | Feldman commitments + verification                                                                                                                                                                  |
| `keygen`      | trusted-dealer keygen + public verifying shares (retained fallback)                                                                                                                                 |
| `dkg`         | Pedersen verifiable DKG: `part1`/`part2`/`part3`, rogue-key PoK, identifiable abort                                                                                                                 |
| `ciphersuite` | FROST(Ed25519, SHA-512) constants + `H1`–`H5`                                                                                                                                                       |
| `sign`        | round-1 `commit` (hedged), round-2 `sign`, `aggregate` (identifiable abort)                                                                                                                         |
| `verify`      | RFC 8032 aggregate `verify` + per-partial `verify_share`                                                                                                                                            |
| `error`       | the crate error enum (`Culprit`, `NonPrimeOrderPoint`, …)                                                                                                                                           |
| `message`     | reserved wire-type module; carries no content yet and freezes on introduction                                                                                                                       |

**`legacy/`** — the archived naive single-key Schnorr scheme: the ROS attack
target (`oracle.rs`) and the BLLOR solver (`ros.rs`). It is **test-only**, a separate
workspace member, `publish = false`, and **never a dependency of `frost-core`** — the
secure scheme and its broken predecessor never share a graph.

**`fuzz/`** — the cargo-fuzz crate (one target per deserializer); its own workspace,
excluded from the build/clippy/test gate, nightly-only.

**The runtime dependency graph consists of six direct dependencies:**
`curve25519-dalek`, `rand_core`, `sha2`, `subtle`, `thiserror`, and `zeroize`.

`deny.toml` allow-lists the production dependency graph (`cargo tree -e normal`) and rejects additional runtime dependencies. `cargo audit` is used to verify that the production dependency graph has no known advisories. The crate is compiled with `#![forbid(unsafe_code)]`.

Development dependencies (`frost-ed25519`, `proptest`, `libfuzzer-sys`, and `legacy`) are used only for testing and are excluded from the runtime dependency graph.

---

## 3. Secret transport

The hard rule is "**no `Serialize` on a secret type**": secrets are `ZeroizeOnDrop`,
carry only a redacting `Debug`, and the crate does not even depend on `serde`. There
is exactly **one principled deviation**, and it is recorded here rather than smuggled.

`dkg::round2::Package` carries a participant's secret share `f_i(ℓ)` to recipient `ℓ`.
Unlike the signing messages — which are public and carry no secret — the
**VSS construction forces** a private dealer→recipient delivery of each share: that is
how a verifiable secret sharing distributes the secret at all. The share therefore must cross a private channel, so `round2::Package` is the only secret-bearing type that provides serialization for transport. The deviation is bounded and hygienic:

- the share inside it is a `SigningShare` — `ZeroizeOnDrop`, redacting `Debug`, no
  `serde`;
- `serialize` returns the bytes wrapped in `Zeroizing<Vec<u8>>`, so the transport
  buffer is itself wiped on drop;
- `deserialize` rejects, never coerces (wrong length, non-canonical/zero recipient,
  non-canonical share);
- it is **for a private, authenticated channel only** — the integrator's transport
  assumption (`THREAT-MODEL.md` §9). The library provides the type's hygiene, not the
  channel.

`tests/zeroization_audit.rs` pins all of this: every other secret type is non-
`Serialize` (structurally — no `serde` dependency) and `round2::Package`'s serialize
returns a zeroizing buffer that round-trips.

---

## 4. Rejected-alternatives table

| Choice                                           | Rejected alternative                                            | Why                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FROST with the binding factor**                | Naive threshold Schnorr (the old scheme)                        | The old scheme is **forgeable in ~50 ms** via the BLLOR ROS attack — committed proof in `legacy/results/ros_forgery.txt`, `ℓ = 256`. FROST's binding factor `ρ_i = H1(group_public ‖ msg ‖ commitment_list ‖ id)` denies the ROS solver its linear system (`tests/ros_resistance.rs`).            |
| **Hand-rolled FROST on a validated group layer** | `frost-ed25519` adopted wholesale as the shipped implementation | Implementing the protocol directly allows the library to define its own validation boundary, serialization rules, and secret-handling types. The independent `frost-ed25519` implementation is used only during testing as a differential oracle and is not part of the runtime dependency graph. |
| **Pedersen DKG as the default keygen**           | Trusted dealer as the only keygen                               | The trusted dealer is a single point that holds the whole secret `s`; it is **retained as a documented fallback** but the DKG is the default so no party ever holds `s`. The DKG reuses the same `KeyPackage`/`PublicKeyPackage` types behind the boundary.                                       |
| **Abort-and-identify DKG**                       | Robust GJKR complaint-and-continue                              | The implementation aborts once an invalid participant is identified. This matches the behaviour of the reference implementation used during differential testing and keeps the protocol compatible with the differential test harness.                                                            |

### 4.1 Strict point decoding

`group.rs` changed once after the initial implementation was considered complete. Coverage-guided fuzzing found that `GElement::from_compressed` accepted non-canonical point encodings (a `y ≥ p`, or a set sign bit on the `x = 0` point). The issue was fixed by enforcing RFC 8032 strict decoding and preserved as a regression test.

- Strict decoding re-encodes the decompressed point and rejects any byte mismatch rather than accepting non-canonical encodings. This avoids multiple byte strings representing the same group element and follows the project's "reject, never coerce" policy.
- This issue affects input validation and canonical encoding. It is not a
  key-recovery or signature-forgery vulnerability.
- **RFC 9591 conformance is unaffected.** A stricter _rejection_ of non-canonical
  inputs changes nothing for canonical vectors: the RFC 9591 KAT suite
  (`tests/rfc9591_kat.rs`) and the ≥10,000-case differential against `frost-ed25519`
  (`tests/differential.rs`) both pass post-fix. The fix narrows the accepted input set
  at the malleability boundary; it alters no valid computation.
- **Evidence:** the finding and both crashing inputs are in `fuzz/README.md`; the
  behavioural regression is pinned in `frost-core/tests/adversarial.rs`;

---

## 5. Cross-references

- Trust boundaries, adversary model, defenses, and out-of-scope items:
  `THREAT-MODEL.md`.
- The ROS forgery artifact: `legacy/results/ros_forgery.txt`; the solver:
  `legacy/src/ros.rs`; the resistance proof: `frost-core/tests/ros_resistance.rs`.
- Supply-chain policy: `deny.toml`. Fuzzing budget and toolchain: `fuzz/README.md`.
- Consolidated adversarial surface: `frost-core/tests/adversarial.rs`. Secret
  hygiene audit: `frost-core/tests/zeroization_audit.rs`.
