# frost-ed25519-kit

A hand-rolled FROST-Ed25519 threshold-signature library: sans-IO, validated
byte-for-byte against the RFC 9591 vectors, `#![forbid(unsafe_code)]` crate-wide,
six shipped dependencies (`cargo tree -e normal -p frost-core` — `curve25519-dalek`,
`rand_core`, `sha2`, `subtle`, `thiserror`, `zeroize`).

## Reproducibility (and where this sits in the portfolio)

Every result here is **hardware-independent**: cryptographic known-answer tests
against the RFC 9591 vectors, a ≥10,000-case differential, and a wall-clock ROS
forgery whose *success* — not its speed — is the claim. They reproduce on any
x86-64 with a stable Rust toolchain; no PMU, no special silicon. This is
deliberate: the sibling repos whose claims *do* depend on hardware (the TCP-server
I/O teardown, the low-latency order book, the transcoding control plane) were
re-run and re-measured on rented AMD EPYC bare metal, and each states which of its
claims are silicon-dependent and which are not. Knowing that difference — and
proving it per repo — is itself the signal.

## How this started, and why that is the credential

This repository began as a "threshold MPC" Solana signer. An audit of that code
found two defects that make a threshold signer worthless: the coordinator could
reconstruct the full private key, and the signing scheme was a naive concurrent
Schnorr that is forgeable. To prove the second is not theoretical, the old scheme
is kept under `legacy/` and attacked directly: a self-mounted ROS (BLLOR 2020)
attack forges a valid signature on a message no honest session ever signed, in
~50 ms over 256 concurrent sessions (`legacy/results/ros_forgery.txt`).

It was then rebuilt as RFC 9591 FROST(Ed25519, SHA-512). The audit-then-rebuild is
the point: the forgery is committed, reproducible evidence that the original
construction was broken, and the new one is checked against the standard rather
than asserted to be correct.

## What it is / is not

- **Is:** a FROST-Ed25519 threshold-signature primitive — the validated group
  layer, secret hygiene, VSS, trusted-dealer keygen, no-dealer DKG, two-round
  signing, and verification.
- **Is not:** a wallet, an application, a frontend, or an RPC client. There is no
  network, no database, and no `solana-*` in the crypto path
  (`docs/ARCHITECTURE.md` §1, the sans-IO boundary).

## Security properties — each with its evidence file

- **RFC 9591 KATs, byte-for-byte, intermediates-first.** Binding factors, the group
  commitment, each partial, and the final signature are checked against the official
  vectors; the first diverging intermediate is reported, not just the final byte
  (`frost-core/tests/rfc9591_kat.rs`).
- **≥10,000-case differential** against the independent `frost-ed25519` crate over
  `2 ≤ t ≤ n ≤ 8`, random signer subsets and messages (`frost-core/tests/differential.rs`).
  The reference crate is a dev-only oracle — never in the shipped graph.
- **No-trusted-dealer Pedersen DKG** with a rogue-key proof of knowledge of the
  polynomial constant term (`frost-core/src/dkg.rs`,
  `frost-core/tests/dkg_differential.rs`, `frost-core/tests/dkg_pok_pin.rs`).
- **Identifiable abort:** the aggregator verifies every partial against its
  verifying share before summing and names the culprit on failure
  (`frost-core/tests/identifiable_abort.rs`).
- **Hedged nonces:** `H3(random ‖ encode(secret))`, so a fully predictable RNG
  still cannot force nonce reuse; single-use is enforced by type
  (`frost-core/src/secret.rs`, `frost-core/src/sign.rs`).
- **Validated, constant-time deserialization:** non-canonical scalars and
  non-prime-order (cofactor / small-subgroup) points are rejected, never coerced;
  no panic on caller- or peer-controlled input (`frost-core/src/group.rs`,
  `frost-core/tests/adversarial.rs`, `frost-core/tests/identifiers.rs`).
- **ROS resistance:** the same solver that forges the legacy oracle returns
  `RosOutcome::NoSolution` against FROST — the binding factor `ρ_i = H1(group_public
  ‖ msg ‖ commitment_list ‖ id)` denies the solver its linear system
  (`frost-core/tests/ros_resistance.rs`).

## Quickstart

```
cargo run --example in_process_2of3
```

`frost-core/examples/in_process_2of3.rs` runs a 3-party Pedersen DKG over
`std::sync::mpsc` channels (no dealer holds the key), then a 2-of-3 FROST
signature, verified under RFC 8032. `frost-core/examples/solana_compat.rs` proves
offline that the output is a standard Ed25519 signature accepted by an independent
verifier (`ed25519-dalek`, `verify_strict`) and that the group key is a valid
base58 Solana address — no SDK, no RPC, no broadcast.

## Trust model and limits

The DKG round-2 shares cross a private, authenticated channel that the library
assumes but does not provide (`docs/THREAT-MODEL.md` §9). The DKG and the
aggregator are **abort-and-identify, not robust**: a detected cheat aborts the run
and names the culprit rather than continuing with the honest subset
(`docs/THREAT-MODEL.md` §11, §8). Read `docs/THREAT-MODEL.md` and
`docs/ARCHITECTURE.md` before relying on it.

```
git clone https://github.com/umangPokhriyall/frost-ed25519-kit
```

## The larger work

The secret-hygiene discipline proven here — split trust, zeroize-after-use,
reject-never-coerce on every untrusted input — is the substrate for handling
secrets that transit an agent sandbox, the portfolio's flagship.
