# frost-ed25519-kit

An implementation of RFC 9591 FROST (Ed25519, SHA-512) in Rust.

The repository also preserves the original naive threshold Schnorr implementation that preceded it, together with a reproducible ROS forgery demonstrating why the redesign was necessary.

Highlights:

- RFC 9591 known-answer vectors (byte-for-byte)
- Differential testing against an independent implementation
- Pedersen distributed key generation (DKG)
- Identifiable abort during signing
- Coverage-guided fuzzing
- `#![forbid(unsafe_code)]`
- Sans-IO design

## Background

This repository began as an experimental threshold signing library for Solana. An audit of that code found two design flaws that defeated the intended security guarantees of the threshold signer: the coordinator could
reconstruct the full private key, and the signing scheme was a naive concurrent
Schnorr that is forgeable. To prove the second is not theoretical, the old scheme
is kept under `legacy/` and attacked directly: a self-mounted ROS (BLLOR 2020)
attack forges a valid signature on a message no honest session ever signed, in
~50 ms over 256 concurrent sessions (`legacy/results/ros_forgery.txt`).

The implementation was then rebuilt as RFC 9591 FROST (Ed25519, SHA-512). The original implementation remains under `legacy/` together with the exploit used to demonstrate the flaw.

## Scope

This repository provides:

- RFC 9591 FROST (Ed25519, SHA-512)
- validated group layer
- Pedersen DKG
- trusted-dealer key generation
- threshold signing
- verification

It does not provide:

- wallets
- RPC
- networking
- databases
- Solana SDK integration

## Security properties

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
- **Validated, constant-time deserialization with strict canonical-encoding
  enforcement:** non-canonical scalars and non-canonical / non-prime-order (cofactor /
  small-subgroup) points are rejected, never coerced — point decoding is RFC 8032
  strict (re-encode-and-compare), not a lenient `decompress`; no panic on caller- or
  peer-controlled input (`frost-core/src/group.rs`, `frost-core/tests/adversarial.rs`,
  `frost-core/tests/identifiers.rs`).
- **ROS resistance:** the same solver that forges the legacy oracle returns
  `RosOutcome::NoSolution` against FROST — the binding factor `ρ_i = H1(group_public
‖ msg ‖ commitment_list ‖ id)` denies the solver its linear system
  (`frost-core/tests/ros_resistance.rs`).
- **Coverage-guided fuzzing:** one libFuzzer target per deserializer (104M+
  executions, 0 crashes after the fix). The fuzzing campaign uncovered a
  non-canonical point-encoding malleability issue in `group.rs`, which was fixed
  by enforcing RFC 8032 strict decoding and preserved as a regression test
  (`fuzz/README.md`, `frost-core/tests/adversarial.rs`).

## Quickstart

Clone the repository and run the in-process example:

```bash
cargo run --example in_process_2of3
```

The example performs:

1. a 3-party Pedersen DKG;
2. a 2-of-3 FROST signing round;
3. verification of the resulting Ed25519 signature.

See `frost-core/examples/solana_compat.rs` for an offline compatibility example showing that the generated signature verifies as a standard Ed25519 signature and that the group public key can be represented as a Solana address.

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

## Repository layout

```text
frost-core/   RFC 9591 implementation
legacy/       Archived naive Schnorr implementation and ROS forgery
fuzz/         Coverage-guided fuzz targets
docs/         Architecture and threat model
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)

## References

- RFC 9591 — FROST
- RFC 8032 — Ed25519
- Benhamouda et al., _One-More Discrete Logarithm and the ROS Attack_ (2020)
