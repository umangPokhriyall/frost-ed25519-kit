## Authoritative specs
- docs/specs/kickoff-brief.md        — strategy, audit, architecture, DoD
- docs/specs/kickoff-amendment-1.md  — adversarial/crypto upgrades (binding)
- docs/specs/phase0-spec.md          — CURRENT: demolition, sans-IO core, group layer
- docs/specs/phase1-spec.md          — FROST signing + KAT/differential harness

## Hard rules
1. frost-core is sans-IO. No tokio/reqwest/diesel/Postgres/solana-* in the crypto path.
   #![forbid(unsafe_code)] crate-wide. group.rs/secret.rs/message.rs/vss.rs FREEZE after P0.
2. Reject, never coerce: non-canonical scalars, non-prime-order points, zero/duplicate
   identifiers -> Result::Err. Zero panic/unwrap/expect on caller- or peer-controlled input.
3. No secret on any non-work path: no Debug derive, no Serialize, no logs, no plaintext-at-rest.
   Zeroize all secret material. Nonces single-use by type.
4. keygen emits verifying shares X_i (public, from VSS commitments) — Phase 1 needs them.
5. Build only from facts: tests assert, specs cite. No marketing words, no emoji, no exclamation.

## Scope discipline
One session, one deliverable. End with cargo build + clippy -D warnings + test, list changes, STOP.

## Freeze record (Phase 0 complete, 2026-06-18)
group.rs, secret.rs, vss.rs are FROZEN: do not change their public contracts. If
Phase 1 signing appears to need a change to any of them, the signing design is
wrong — STOP and ask. keygen.rs is stable but not frozen (Phase 2 adds Pedersen
DKG behind the same KeyPackage/PublicKeyPackage/SigningShare types). message.rs is
not yet implemented (no Phase 0 wire types were needed); it freezes on
introduction. The sans-IO boundary is law from here on.
