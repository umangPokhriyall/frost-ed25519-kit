# frost-ed25519-kit — Final Definition-of-Done Audit (the distribution gate)

**Companion to:** `kickoff-brief.md` §6, `kickoff-amendment-1.md`, `phase4-spec.md` §9.
**Purpose:** the distribution gate NORTH-STAR §6 names. Every `kickoff-brief.md` §6
item (1–11) and every `kickoff-amendment-1.md` net-effect addition is mapped to its
committed evidence file, with a status. Distribution is authorized only when every
code row is **GREEN** *and* the owner clears item 11 (the comprehension gate).

This is a record, not a vibe: each row cites a file in this repository, and the two
machine-checkable invariants were re-confirmed when this audit was written
(2026-06-28):

- `cargo tree -e normal -p frost-core` is the **six shipped crates**: `curve25519-dalek`,
  `rand_core`, `sha2`, `subtle`, `thiserror`, `zeroize`. No `ed25519-dalek`, `bs58`,
  `frost-ed25519`, `legacy`, `proptest`, or `serde_json` in the shipped graph (all
  dev/tooling-only).
- `#![forbid(unsafe_code)]` is present in both shipped crates (`frost-core/src/lib.rs:26`,
  `legacy/src/lib.rs:13`) and as the workspace lint `unsafe_code = "forbid"`
  (`Cargo.toml:26`).

---

## Brief §6 — Hard Definition of Done

| # | Brief DoD item | Evidence (committed) | Status |
|---|---|---|---|
| 1 | Single sans-IO library; no net/DB/Solana-SDK in the crypto path; `#![forbid(unsafe_code)]` crate-wide; `orchestrator`/`node`/`store`/`nodeDb` deleted | `cargo tree -e normal -p frost-core` (six crates); `frost-core/src/lib.rs:26`; `docs/ARCHITECTURE.md` §1; P0 demolition commit `ed73f72` (shell dirs absent from tree) | GREEN |
| 2 | FROST signing passes RFC 9591 KATs byte-for-byte and differentially matches `frost-ed25519` on ≥10,000 randomized cases across varied `(t, n)` | `frost-core/tests/rfc9591_kat.rs`; `frost-core/tests/differential.rs` (`cases: 10_000`, `2 ≤ t ≤ n ≤ 8`) | GREEN |
| 3 | Reconstruction proven: any `t` reconstruct; any `t−1` reveal nothing | `frost-core/tests/reconstruction.rs`; `frost-core/tests/dkg_differential.rs` | GREEN |
| 4 | Concurrent-session forgery resistance: ROS attack succeeds vs the archived naive scheme, fails vs FROST, in a committed test | `legacy/results/ros_forgery.txt` (`ℓ=256`, wall-clock, out-of-set proof); `frost-core/tests/ros_resistance.rs` (negative control returns `RosOutcome::NoSolution`) | GREEN |
| 5 | All secret material `Zeroizing`/zeroized on drop; secrets never `Debug` or log; single-use nonces by type; a leak-audit test or lint confirms it | `frost-core/src/secret.rs`; `frost-core/tests/zeroization_audit.rs` | GREEN |
| 6 | Validated deserialization: non-canonical scalars and non-prime-order points rejected, proven by adversarial tests; zero `unwrap`/`expect`/`panic!` on peer-controlled input | `frost-core/src/group.rs`; `frost-core/tests/adversarial.rs`; `frost-core/tests/identifiers.rs`; `fuzz/` (104.6M execs, 0 crashes). **Strengthened in Phase 4:** the coverage-guided fuzz run found `GElement::from_compressed` accepting non-canonical point encodings; fixed with RFC 8032 strict decoding (`group.rs`), regression-pinned (`adversarial.rs`), re-fuzzed clean (`fuzz/README.md`) | GREEN |
| 7 | `docs/THREAT-MODEL.md` complete: trust boundaries, adversary model, ROS defense, rogue-key, small-subgroup, coordinator trust, out-of-scope | `docs/THREAT-MODEL.md` §1–§11 | GREEN |
| 8 | `cargo audit` + `cargo deny` clean; dependency allowlist respected; `clippy -D warnings`; CI green | `deny.toml`; `.github/workflows/ci.yml`; §3.4 re-verification (advisories/bans/licenses/sources ok; only the out-of-graph informational `atomic-polyfill` warning, decision recorded in `deny.toml`) | GREEN |
| 9 | `docs/ARCHITECTURE.md`: sans-IO boundary, message types, rejected alternatives (naive threshold Schnorr and *why* broken; trusted-dealer vs Pedersen DKG; hand-roll-plus-differential vs `frost-ed25519` wholesale) | `docs/ARCHITECTURE.md` §1, §2, §4 (rejected-alternatives table) | GREEN |
| 10 | `README.md` positions a systems-crypto primitive, 60-second grasp, no app glue; `solana_compat` proves Ed25519/Solana-address compatibility offline (no RPC/broadcast); committed `.env` purged; `diesel.toml` gone | `README.md`; `frost-core/examples/solana_compat.rs` (independent `ed25519-dalek` `verify_strict`, base58 address); `.env`/`diesel.toml` absent from tree and history | GREEN |
| 11 | **Self-audit (comprehension gate):** the owner can re-derive the FROST binding factor from memory and explain why it defeats ROS where `R = ΣR_i` does not | **owner (human)** — see the gate statement below | **OWNER GATE — pending** |

---

## Amendment 1 — net-effect additions to the DoD

| Amendment item | Evidence (committed) | Status |
|---|---|---|
| §6.4 (revised): ROS forgery succeeds vs `legacy/` with `ℓ`, wall-clock, out-of-set proof committed; negative-control argument in `ros_resistance.rs` | `legacy/results/ros_forgery.txt`; `frost-core/tests/ros_resistance.rs` (module doc states the binding-factor argument) | GREEN |
| §6.2a (new): intermediate KATs (`ρ_i`, `R`, `z_i`) pass *before* the final-signature KAT | `frost-core/tests/rfc9591_kat.rs` (intermediates-first ordering) | GREEN |
| §6.6a (new): zero and duplicate identifiers rejected at deserialization, with adversarial tests | `frost-core/src/group.rs` (`validate_identifier_set`, nonzero `Identifier`); `frost-core/tests/identifiers.rs`; `frost-core/tests/dkg_adversarial.rs` | GREEN |
| §6.6b (new): every partial verified against its `X_i` before aggregation; a bad partial yields `Culprit(id)`, proven by test | `frost-core/src/verify.rs` (`verify_one_share`); `frost-core/src/sign.rs` (`aggregate`); `frost-core/tests/identifiable_abort.rs`; DKG `Culprit` in `frost-core/src/dkg.rs` | GREEN |
| §6.5a (new): nonces use the hedged `H3(random ‖ secret)` construction; stated in the threat model | `frost-core/src/sign.rs` (`commit`); `frost-core/src/dkg.rs` (PoK nonce); `docs/THREAT-MODEL.md` §7; determinism tests in `frost-core/src/sign.rs` | GREEN |
| Upgrade 5: identifier domain discipline (Phase 0) | `frost-core/src/group.rs`; `frost-core/tests/identifiers.rs` | GREEN |

---

## Item 11 — the owner comprehension gate (NORTH-STAR §4)

Every code row above is **GREEN**. Distribution remains **NOT AUTHORIZED** until the
owner clears item 11. The gate is met when the owner can re-derive, from memory:

- the FROST partial-signature equation `z_i = d_i + ρ_i·e_i + λ_i·c·s_i`, and the
  aggregate `(R, z)` with `R = Σ_j (D_j + ρ_j·E_j)`, `c = H2(R ‖ A ‖ msg)`;
- the binding-factor/ROS argument: `ρ_i = H1(group_public ‖ msg ‖ commitment_list ‖ id)`
  is a function of the message and the **full** commitment list, so the adversary
  cannot know the challenge coefficients before fixing the commitments — the linear
  system the ROS solver needs never exists. With a plain `R = Σ R_i` (no binding
  factor) that system *does* exist, which is exactly the legacy forgery in
  `legacy/results/ros_forgery.txt`;
- the DKG rogue-key PoK verification `μ_i·G == R_i + c_i·φ_{i,0}` with
  `c_i = H_dkg(id ‖ φ_{i,0} ‖ R_i)`.

This is a human gate. It cannot be cleared by Claude Code or by any test, and it is
not marked green here. Until the owner clears it, the gate stays open.
