## Authoritative specs
- docs/specs/kickoff-brief.md        — strategy, audit, architecture, DoD
- docs/specs/kickoff-amendment-1.md  — adversarial/crypto upgrades (binding)
- docs/specs/phase0-spec.md          — demolition, sans-IO core, group layer (DONE, FROZEN)
- docs/specs/phase1-spec.md          — FROST signing + KAT/differential (DONE, FROZEN)
- docs/specs/phase2-spec.md          — Pedersen DKG + PoK + identifiable abort (DONE, FROZEN)
- docs/specs/phase3-spec.md          — ROS forgery, adversarial, fuzz, audits, threat model (DONE, FROZEN)
- docs/specs/phase4-spec.md          — CURRENT: examples, README, distribution, final audit

## Hard rules (consolidated)
1. frost-core is sans-IO. No tokio/reqwest/diesel/Postgres/solana-* in the crypto path.
   #![forbid(unsafe_code)] in every shipped crate. ALL frost-core + legacy source is FROZEN.
2. Reject, never coerce: non-canonical scalars, non-canonical/non-prime-order points,
   zero/duplicate ids -> Err. Point decoding is RFC 8032 strict (canonical y, canonical
   sign bit), not dalek's lenient decompress. Zero panic/unwrap/expect on caller- or
   peer-controlled input.
3. No secret on any non-work path: no Debug derive, no Serialize (except round2::Package,
   secret-in-transit over a private+authenticated channel), no logs. Zeroize all secret
   material; nonces hedged H3(random || share) and single-use by type.
4. Hand-rolled crypto is validated against the source of truth: RFC 9591 KATs byte-for-byte
   (intermediates-first), differential vs frost-ed25519 (DEV-DEP ORACLE ONLY, never shipped).
5. DKG is abort-and-identify (supersedes the brief's "complaint round"): bad PoK/share/rogue key
   -> Culprit(id). PoK verified, rogue-key-resistant.
6. ROS: the legacy scheme is forgeable in ~49 ms (legacy/results/ros_forgery.txt); FROST returns
   RosOutcome::NoSolution (structural). The binding-factor argument lives in ros_resistance.rs.
7. Shipped graph = six crates (curve25519-dalek, rand_core, sha2, subtle, thiserror, zeroize).
   Verify with cargo tree -e normal. legacy/fuzz/ed25519-dalek/bs58/frost-ed25519/proptest/
   serde_json are dev/tooling-only.
8. Build from facts: tests assert, specs cite, prose cites committed files. No marketing language,
   no emoji, no exclamation, no adjective a number hasn't earned.

## Scope discipline
One session, one deliverable. End with cargo build + clippy -D warnings + test (fuzz excluded),
list changes, STOP.

## Freeze record
group.rs, secret.rs, vss.rs froze at Phase 0 (2026-06-18); sign.rs, verify.rs, dkg.rs,
keygen.rs froze as their phases completed (P1/P2). Do not change their public contracts. If a
later phase appears to need such a change, the design is wrong — STOP and ask.

One authorized post-freeze exception (Phase 4, 2026-06-28): the coverage-guided fuzz run found
that group.rs `GElement::from_compressed` accepted NON-CANONICAL point encodings (y >= the
field prime, or a set sign bit on x = 0) because dalek's `decompress()` silently canonicalizes
them — a malleability vector and a "reject, never coerce" violation the Phase 3 bounded fuzz
floor missed. Fixed by adding an RFC 8032 strict re-encode-and-compare check; regression-pinned
in tests/adversarial.rs; confirmed 0 crashes on re-fuzz (fuzz/README.md). group.rs is re-frozen.
