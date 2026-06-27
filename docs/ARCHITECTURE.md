# frost-ed25519-kit — Architecture

How the pieces fit, why the boundaries are where they are, and the
rejected-alternatives record. Companion to `THREAT-MODEL.md`. This document closes
the Phase 2 §9.8 debt: the secret-in-transit recording (§3) and the
rejected-alternatives table (§4).

---

## 1. The sans-IO boundary

`frost-core` is **pure functions and explicit state machines**. There is no I/O on
the trust path: no `tokio`, `reqwest`, `diesel`, Postgres, or `solana-*` anywhere in
the crate, and there never will be. Keygen, signing, aggregation, verification, and
the DKG rounds are all `(inputs) -> Result<outputs, Error>`; the caller drives the
protocol and owns **all** transport, scheduling, and persistence.

This is the same discipline that froze the TCP `core` in the predecessor: the trust-
critical logic is testable in-process, deterministic, and unentangled from the
network. It is also what makes the differential harness possible — every step can be
compared byte-for-byte against the reference implementation without a socket in the
way. The boundary is law: if a feature appears to need I/O inside `frost-core`, the
design is wrong.

---

## 2. Module map and the shipped graph

**Frozen core** (`frost-core/src/`, all FROZEN after their phase — public contracts
do not change):

| module | responsibility |
|---|---|
| `group` | validated, constant-time scalar/point/identifier layer — the only place raw `curve25519-dalek` types are touched; rejects non-canonical scalars, non-prime-order points, zero/duplicate identifiers |
| `secret` | zeroizing secret types (`SigningShare`, `SigningNonces`, `SecretPolynomial`); single-use nonces by type |
| `vss` | Feldman commitments + verification |
| `keygen` | trusted-dealer keygen + public verifying shares (retained fallback) |
| `dkg` | Pedersen verifiable DKG: `part1`/`part2`/`part3`, rogue-key PoK, identifiable abort |
| `ciphersuite` | FROST(Ed25519, SHA-512) constants + `H1`–`H5` |
| `sign` | round-1 `commit` (hedged), round-2 `sign`, `aggregate` (identifiable abort) |
| `verify` | RFC 8032 aggregate `verify` + per-partial `verify_share` |
| `error` | the crate error enum (`Culprit`, `NonPrimeOrderPoint`, …) |
| `message` | reserved wire-type module; carries no content yet and freezes on introduction |

**`legacy/`** — the archived naive single-key Schnorr scheme: the Phase 3 ROS attack
target (`oracle.rs`) and the BLLOR solver (`ros.rs`). It is **test-only**, a separate
workspace member, `publish = false`, and **never a dependency of `frost-core`** — the
secure scheme and its broken predecessor never share a graph.

**`fuzz/`** — the cargo-fuzz crate (one target per deserializer); its own workspace,
excluded from the build/clippy/test gate, nightly-only.

**The shipped graph is six direct dependencies and nothing else:**
`curve25519-dalek`, `rand_core`, `sha2`, `subtle`, `thiserror`, `zeroize`. This is
enforced, not aspirational: `deny.toml` allow-lists exactly the `-e normal` closure
and bans everything else (plus a permissive-license policy and a crates.io-only
source policy), and `cargo audit` reports zero advisories in that graph. A threshold-
signature primitive with **six audited shipped dependencies** and
**`#![forbid(unsafe_code)]`** crate-wide is itself a security argument: a tiny,
reviewable, memory-safe surface. The dev/test graph (the `frost-ed25519` differential
oracle, `proptest`, `legacy`, `libfuzzer-sys`) is excluded from the shipped count and
verified absent with `cargo tree -e normal -p frost-core`.

---

## 3. Secret-in-transit recording (the explicit Phase 2 §9.8 closure)

The hard rule is "**no `Serialize` on a secret type**": secrets are `ZeroizeOnDrop`,
carry only a redacting `Debug`, and the crate does not even depend on `serde`. There
is exactly **one principled deviation**, and it is recorded here rather than smuggled.

`dkg::round2::Package` carries a participant's secret share `f_i(ℓ)` to recipient `ℓ`.
Unlike the Phase 1 signing messages — which are public and carry no secret — the
**VSS construction forces** a private dealer→recipient delivery of each share: that is
how a verifiable secret sharing distributes the secret at all. The share therefore
*must* cross a channel, so `round2::Package` *must* be serializable. The deviation is
bounded and hygienic:

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

Each row is now substantiated by Phase 3 evidence.

| Choice | Rejected alternative | Why |
|---|---|---|
| **FROST with the binding factor** | Naive threshold Schnorr (the old scheme) | The old scheme is **forgeable in ~49 ms** via the BLLOR ROS attack — committed proof in `legacy/results/ros_forgery.txt`, `ℓ = 256`. FROST's binding factor `ρ_i = H1(group_public ‖ msg ‖ commitment_list ‖ id)` denies the ROS solver its linear system (`tests/ros_resistance.rs`). This single artifact is why the rebuild was necessary. |
| **Hand-rolled FROST on a validated group layer** | `frost-ed25519` adopted wholesale as the shipped implementation | The hand-roll is the signal: full control of the secret hygiene, the validation boundary, and the sans-IO contract, with a six-crate surface. `frost-ed25519` is retained instead as the **differential oracle** — every intermediate (binding factors, group commitment, partials, final signature) is checked against it and the RFC 9591 KATs, which is precisely what makes hand-rolling safe rather than reckless. |
| **Pedersen DKG as the default keygen** | Trusted dealer as the only keygen | The trusted dealer is a single point that holds the whole secret `s`; it is **retained as a documented fallback** but the DKG is the default so no party ever holds `s`. The DKG reuses the same `KeyPackage`/`PublicKeyPackage` types behind the boundary. |
| **Abort-and-identify DKG** | Robust GJKR complaint-and-continue | Abort-and-identify names the culprit and stops, **matching the ecosystem oracle** (`frost-ed25519`) and preserving the differential gate — a complaint-and-continue round would diverge from the oracle and forfeit byte-for-byte comparison. This supersedes the brief's original "complaint round." Robustness (continue with the honest subset) is explicitly out of scope (`THREAT-MODEL.md` §11). |

---

## 5. Cross-references

- Trust boundaries, adversary model, defenses, and out-of-scope items:
  `THREAT-MODEL.md`.
- The ROS forgery artifact: `legacy/results/ros_forgery.txt`; the solver:
  `legacy/src/ros.rs`; the resistance proof: `frost-core/tests/ros_resistance.rs`.
- Supply-chain policy: `deny.toml`. Fuzzing budget and toolchain: `fuzz/README.md`.
- Consolidated adversarial surface: `frost-core/tests/adversarial.rs`. Secret
  hygiene audit: `frost-core/tests/zeroization_audit.rs`.
