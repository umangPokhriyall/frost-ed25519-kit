# frost-ed25519-kit — Phase 4 Specification: Artifacts, Examples, Distribution, and the Final Audit

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0/1/2/3-spec.md`, and the current `CLAUDE.md`. Read all first.
**This is the complete, authoritative Phase 4 spec.** It covers the runnable examples (in-process DKG→sign→verify, and an offline `solana_compat` interop proof), the `README.md`, the distribution thread, CI, the closure of two carried debts (`CLAUDE.md` currency and the real coverage-guided fuzz run), and the final whole-repo Definition-of-Done audit that gates distribution.
**Audience:** Claude Code, plus a short set of one-time manual commands for the human (§0).

---

## 0. Prerequisite manual setup (human, run once — some need sudo)

Phase 4's core deliverables (examples, README, thread, CI) need **no special tooling**. The two *strengthening* steps — the real libFuzzer run (§3.3) and the audit re-verification from installed binaries (§3.4) — need the following. Run these yourself before Session 4.3; if you skip them, the Phase 3 bounded-harness floor and the prior audit remain the committed evidence, and the spec says so honestly.

```bash
# --- Real coverage-guided fuzzing (Session 4.3) ---
rustup toolchain install nightly          # cargo-fuzz requires nightly (user-space, no sudo)
sudo apt-get update && sudo apt-get install -y clang   # libFuzzer needs a C/C++ toolchain (SUDO)
cargo install cargo-fuzz                   # installs to ~/.cargo/bin (no sudo)

# --- Supply-chain tooling, installed permanently instead of the Phase 3 /tmp musl binaries ---
cargo install cargo-deny cargo-audit       # ~/.cargo/bin (no sudo)

# --- Optional: rename the GitHub repo to match the crate (interactive auth) ---
gh auth login                              # one-time, interactive
gh repo rename frost-ed25519-kit           # run from inside the repo; GitHub keeps a redirect
git remote set-url origin git@github.com:<your-user>/frost-ed25519-kit.git
```

Only two require human/elevated action: `sudo apt-get install clang` and the interactive `gh auth login`. Everything else is user-space `cargo`/`rustup`. The session prompts (Appendix B) assume these are done and have Claude Code run the `cargo`-level commands; each prompt states the fallback if they are not.

---

## 1. Phase 4 in one paragraph

Make the finished primitive legible and distributable without changing a line of shipped logic. Write two runnable examples that a reviewer can execute in seconds — an in-process `t`-of-`n` DKG→sign→verify over channels, and an offline `solana_compat` proof that the FROST output is a standard Ed25519 signature an *independent* verifier accepts and that the group key is a real Solana address (no SDK, no RPC, no broadcast). Write the `README.md` that conveys what this is and why it is sound in sixty seconds, every number citing a committed file. Write the distribution thread that leads with the true, arresting fact — a self-forged signature in ~49 ms, then the rebuild — findings not hype. Add CI that gates the stable workspace and runs the supply-chain checks. Close the two carried debts: bring `CLAUDE.md` current, and replace the bounded fuzz floor with a real coverage-guided run (tooling in §0). Then run the final whole-repo Definition-of-Done audit against `kickoff-brief.md` §6 and the amendment, each item mapped to its evidence file — the gate NORTH-STAR §6 names before distribution.

### 1.1 Frozen / reused
- **Every `frost-core` and `legacy` source module is frozen.** Phase 4 adds examples, prose, CI, and project-hygiene fixes only. No shipped logic, no test-logic changes. If an example appears to need a core change, the example is wrong — STOP and ask.
- **Examples are `frost-core/examples/*.rs`** — auto-discovered targets that use dev-dependencies; they never enter the shipped graph.
- **The shipped graph stays the six crates.** New dev-dependencies (`ed25519-dalek`, `bs58`) are example-only; re-verify with `cargo tree -e normal`.

---

## 2. Workspace additions & dependencies

```
frost-core/examples/in_process_2of3.rs   # NEW — n parties over channels: DKG → sign → verify, no I/O beyond stdout
frost-core/examples/solana_compat.rs     # NEW — offline: FROST sig verified by an INDEPENDENT verifier + base58 Solana address
README.md                                # REWRITE — 60-second systems-crypto primitive, no app glue, every number cited
docs/x-thread.md                         # NEW — distribution thread, findings-first, every claim cites a committed file
.github/workflows/ci.yml                 # NEW — build + clippy -D + test + cargo deny + cargo audit
fuzz/README.md                           # UPDATE — real libFuzzer numbers (§3.3), if §0 tooling installed
CLAUDE.md                                # REWRITE — bring current across all phases (Appendix A)
```

Dependency additions (example-only dev-deps; shipped graph unchanged):
```toml
# frost-core dev-dependencies:
ed25519-dalek = "2"   # INDEPENDENT standard Ed25519 verifier for solana_compat — not our verify.rs
bs58          = "0.5" # Solana address encoding (base58 of the 32-byte pubkey) for solana_compat
```
Re-verify at phase end: `cargo tree -e normal -p frost-core` is still the six crates; `ed25519-dalek`, `bs58`, `frost-ed25519`, `legacy`, `proptest`, `serde_json` are all dev-only.

---

## 3. Debt closure (carried from Phase 3)

### 3.1 `CLAUDE.md` currency (P3 agent's flagged follow-up)
`CLAUDE.md` still lists phase0 as CURRENT and omits the phase1–3 hard rules and spec references. Rewrite it (Appendix A) to list all five specs + the amendment, and the consolidated hard-rule set. This is the project's guidance map; a stale map is a real defect for the next reader (human or agent).

### 3.2 `legacy/results/ros_forgery.txt` wall-clock determinism
The wall-clock line re-measures whenever the legacy suite runs (inherent to a benchmark). Leave the measurement live, but add a one-line header to the file noting it is a re-measured benchmark figure (expect single-digit-to-low-tens-of-ms variance), so a reader does not mistake the churn for instability. Do not freeze it to a literal — that would be a fabricated constant, which violates measure-never-guess.

### 3.3 Real coverage-guided fuzz run (replaces the bounded floor) — needs §0 tooling
With nightly + `cargo-fuzz` installed, run each of the six targets under libFuzzer for a committed budget (e.g. `-runs=` a fixed count, or `-max_total_time=` a fixed wall-time per target). Update `fuzz/README.md` with the **real** numbers: per-target exec count, wall-time, and `0 crashes`, reported as measured — not "clean." Keep the bounded stable harness as the CI-runnable floor. **If §0 tooling is not installed:** leave the Phase 3 bounded-harness numbers as the committed evidence and state in `fuzz/README.md` that the coverage-guided run is pending local execution. Either way, the report is honest about what was actually run.

### 3.4 Audit re-verification + the lockfile orphan
Re-run `cargo deny check` and `cargo audit` from the §0-installed binaries; confirm the Phase 3 result (advisories/bans/licenses/sources OK; shipped-graph advisory count zero). The `atomic-polyfill` entry is a `Cargo.lock` orphan with no path in the shipped graph (`cargo tree -i atomic-polyfill` finds nothing) — **leave it documented, do not run a blanket `cargo update`** that would churn the lockfile of a security primitive for an informational, out-of-graph advisory. Record the decision in `deny.toml` comments or `ARCHITECTURE.md` if not already there.

---

## 4. `examples/in_process_2of3.rs` — the 60-second runnable proof

`n` participants in one process, messages routed over `std::sync::mpsc` channels (channels, not function calls, so the sans-IO boundary is visible and the example reads as a real multi-party run). Flow:
1. Run the Pedersen DKG for `n = 3` (`part1` → broadcast → `part2` → private shares → `part3`), producing each participant's `KeyPackage` and the shared `PublicKeyPackage`.
2. Choose a `t = 2` signer set; run FROST `commit` → `sign` → `aggregate`.
3. `verify` the aggregate signature; print the group public key (hex) and "verified".

No file or network I/O beyond stdout. The example is also the README's quickstart. Keep it under ~120 lines and commented so the protocol shape is legible. `cargo run --example in_process_2of3` succeeds.

---

## 5. `examples/solana_compat.rs` — the offline interop proof

The one artifact that earns the "Ed25519 / Solana-compatible" claim, with no SDK and no network. Flow:
1. Keygen (trusted-dealer or DKG) → `group_public`; FROST-sign a fixed message.
2. **Independent verification:** verify the signature with `ed25519-dalek` (a *different* implementation than our `verify.rs` and than the `frost-ed25519` differential oracle) — this is the interoperability claim: any standard Ed25519 verifier accepts a FROST signature.
3. **Address:** derive and print the Solana address as `bs58::encode(group_public_32_bytes)` — a normal Ed25519 public key *is* a Solana address.
4. A comment block stating exactly what is and is not proven: *proven* — the threshold signature is a standard RFC-8032 Ed25519 signature accepted by an independent verifier, and the group key is a valid Solana address; *not done* — no broadcast, no RPC, no Solana SDK, no on-chain transaction.

**Verify-never-assume (the interop subtlety):** Ed25519 has verification variants (`ed25519-dalek`'s `verify` vs `verify_strict`; cofactored vs strict canonical checks). Determine which variant accepts the FROST signature and use it, documenting the exact call — do not assume `verify_strict` passes; measure it. An honestly-generated FROST `R` should pass strict verification, but confirm rather than guess. `cargo run --example solana_compat` succeeds and prints the address.

---

## 6. `README.md` — the 60-second grasp

Rewrite from the application-glue original into a systems-crypto primitive README. No marketing language, no emoji, no exclamation; every quantitative claim cites its committed file (the writing standard, enforced). Structure:

- **One line:** a hand-rolled FROST-Ed25519 threshold-signature library — sans-IO, validated against the RFC 9591 vectors, `#![forbid(unsafe_code)]`, six shipped dependencies.
- **The headline (honest origin story):** this repo began as a "threshold MPC" Solana signer whose coordinator could reconstruct the key and whose signing scheme was forgeable; a self-mounted ROS attack forges a signature on an unsigned message in ~49 ms (`legacy/results/ros_forgery.txt`); it was rebuilt as RFC 9591 FROST. The audit-then-rebuild *is* the credential.
- **What it is / is not:** a threshold-signature primitive; not a wallet, not an app, no frontend, no RPC.
- **Security properties (each with its evidence file):** RFC 9591 KATs byte-for-byte, intermediates-first (`tests/rfc9591_kat.rs`); 10k-case differential vs `frost-ed25519` (`tests/differential.rs`); no-trusted-dealer Pedersen DKG with rogue-key PoK (`dkg.rs`, `tests/dkg_*`); identifiable abort; hedged nonces; constant-time validated deserialization (cofactor + canonical checks); ROS resistance with the binding-factor argument (`tests/ros_resistance.rs`).
- **Quickstart:** the `in_process_2of3` example.
- **Trust model & limits:** a two-line summary pointing to `docs/THREAT-MODEL.md` and `docs/ARCHITECTURE.md`, naming the DKG private-channel assumption and the abort-and-identify (non-robust) property up front.
- **One closing line on the larger work:** the secret-hygiene discipline here (split trust, zeroize-after-use, validated handling) is the substrate for secrets transiting an agent sandbox — the portfolio's flagship. One sentence, no more.

### 6.1 If the repo is renamed (§0)
If `gh repo rename` was run, update any in-repo references and the clone URL in the README to `frost-ed25519-kit`. If not, keep the README positioning ("a FROST-Ed25519 threshold-signature primitive") regardless of the URL — the positioning is independent of the slug.

---

## 7. `docs/x-thread.md` — distribution (findings, not hype)

NORTH-STAR §7: proof-first, post findings, lead with the link, no ask. Draft a thread built **only** from committed numbers; invent nothing. Suggested arc:
1. Lead with the true, arresting fact: shipped a "threshold MPC" signer, audited it, found the coordinator held the key and the scheme was forgeable — so forged it on purpose, a valid signature on an unsigned message in ~49 ms.
2. The real audit findings (coordinator-held shares, naive concurrent Schnorr, plaintext shares) — brief, factual.
3. The forgery: the number, what ROS is in one sentence, the evidence file.
4. The rebuild: hand-rolled FROST-Ed25519, validated byte-for-byte against RFC 9591 vectors (intermediates-first) and 10k differential cases vs the reference crate.
5. No trusted dealer: Pedersen DKG with a rogue-key proof of knowledge.
6. Why FROST resists what the old scheme didn't: the binding factor denies the solver its linear system — the structural argument, one paragraph.
7. The surface: `#![forbid(unsafe_code)]`, six audited dependencies, sans-IO.
8. Close: link to the repo and `THREAT-MODEL.md`. No request.

**Hard rule (the writing standard):** every claim cites a committed file; no adjective the number has not earned. The thread is reviewed against the repo before it is called done.

---

## 8. CI — `.github/workflows/ci.yml`

A workflow on push/PR that gates the stable workspace and runs the supply-chain checks (so "CI green" in the brief DoD is real):
- `cargo build --workspace`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --workspace` (the `fuzz/` crate is excluded via the root `exclude`)
- `cargo deny check` (e.g. the `EmbarkStudios/cargo-deny-action`)
- `cargo audit` (e.g. the `rustsec/audit-check` action)

Pin the toolchain (stable, a specific version) for reproducibility. A nightly fuzz job is optional and, if added, runs a short bounded pass — not on the critical path. CI must be green on the commit that is distributed.

---

## 9. The final whole-repo DoD audit (the distribution gate)

Before any distribution, walk `kickoff-brief.md` §6 (items 1–11) and the `kickoff-amendment-1.md` net-effect additions, mapping each to its committed evidence. Produce this as a short `docs/specs/dod-audit.md` (or a section in the PR description) so the gate is a record, not a vibe. The mapping:

| Brief DoD | Evidence |
|---|---|
| 1 sans-IO lib; no net/db/sdk in crypto path; `forbid(unsafe)`; shell deleted | workspace tree; `cargo tree -e normal`; P0 demolition commit |
| 2 FROST KATs byte-for-byte + ≥10k differential | `tests/rfc9591_kat.rs`, `tests/differential.rs` |
| 3 reconstruction t / t-1-reveals-nothing | `tests/reconstruction.rs`; `tests/dkg_differential.rs` |
| 4 ROS forgery succeeds vs legacy, fails vs FROST | `legacy/results/ros_forgery.txt`, `tests/ros_resistance.rs` |
| 5 zeroize; no Debug/log leak; single-use nonces | `secret.rs`, `tests/zeroization_audit.rs` |
| 6 validated deser rejects non-canonical/non-prime-order; no panic | `group.rs`, `tests/identifiers.rs`, `tests/adversarial.rs`, `fuzz/` |
| 7 THREAT-MODEL.md | `docs/THREAT-MODEL.md` |
| 8 cargo audit + deny clean; clippy | `deny.toml`, CI, §3.4 |
| 9 ARCHITECTURE.md + rejected-alternatives | `docs/ARCHITECTURE.md` |
| 10 README primitive; solana_compat offline | `README.md`, `examples/solana_compat.rs` |
| 11 self-audit comprehension gate | **owner (human)** |
| Amendment: intermediates-first KAT | `tests/rfc9591_kat.rs` staged |
| Amendment: identifiable abort (partial verify) | `tests/identifiable_abort.rs`, `dkg` Culprit |
| Amendment: hedged nonces | `sign.rs` commit, `dkg.rs` PoK; determinism tests |
| Amendment: identifier discipline | `tests/identifiers.rs`, `tests/dkg_adversarial.rs` |

Item 11 is the human gate NORTH-STAR §4 names: the owner re-derives, from memory, the FROST partial `z_i = d_i + ρ_i e_i + λ_i c s_i`, the binding-factor/ROS argument, and the DKG PoK verification. Distribution is authorized only when every code row is green **and** the owner clears item 11.

---

## 10. Phase 4 Definition of Done

1. `frost-core`/`legacy` source modules byte-for-byte unchanged (`git diff` confirms); no shipped logic added.
2. `examples/in_process_2of3.rs` runs (`cargo run --example in_process_2of3`): DKG → 2-of-3 sign → verify, channel-routed, stdout only.
3. `examples/solana_compat.rs` runs: FROST signature verified by the **independent** `ed25519-dalek` verifier (exact variant documented), base58 Solana address printed, the proven/not-proven comment block present; no SDK/RPC/broadcast.
4. Shipped graph still the six crates; `ed25519-dalek`/`bs58` dev-only (`cargo tree -e normal` proves it); `#![forbid(unsafe_code)]` intact.
5. `README.md` rewritten per §6: systems-crypto primitive, 60-second grasp, no app glue, every number cites its file, the honest origin story present.
6. `docs/x-thread.md` per §7: findings-first, every claim cites a committed file, no marketing, no ask.
7. `.github/workflows/ci.yml` present and green on the distributed commit: build + clippy -D + test + deny + audit; fuzz excluded.
8. `CLAUDE.md` brought current (Appendix A): all five specs + amendment listed; consolidated hard rules.
9. `legacy/results/ros_forgery.txt` carries the benchmark-variance header (§3.2).
10. Fuzz evidence honest (§3.3): real libFuzzer numbers if §0 tooling installed, else the bounded floor with the pending-local note. `cargo deny`/`cargo audit` re-verified (§3.4); lockfile-orphan decision recorded.
11. `docs/specs/dod-audit.md` (or PR section) maps every brief/amendment DoD item to its evidence file; every code row green.
12. `cargo build`, `cargo clippy --all-targets -D warnings`, `cargo test --workspace` clean (fuzz excluded).
13. **Owner gate (human):** the comprehension self-audit (§9 item 11) is cleared. Until then, distribution is not authorized.

---

## Appendix A — `CLAUDE.md` (full rewrite, current as of Phase 4)

```markdown
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
2. Reject, never coerce: non-canonical scalars, non-prime-order points, zero/duplicate ids -> Err.
   Zero panic/unwrap/expect on caller- or peer-controlled input.
3. No secret on any non-work path: no Debug derive, no Serialize (except round2::Package,
   secret-in-transit over a private+authenticated channel), no logs. Zeroize all secret material;
   nonces hedged H3(random || share) and single-use by type.
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
```

## Appendix B — Claude Code execution plan (Phase 4)

| # | Session | Deliverable | Done when | Needs §0 tooling? |
|---|---|---|---|---|
| 4.1 | Examples | `examples/in_process_2of3.rs`, `examples/solana_compat.rs`; dev-deps `ed25519-dalek`, `bs58` | both `cargo run --example` succeed; independent verify + address printed | no |
| 4.2 | README + thread + CI | `README.md` rewrite, `docs/x-thread.md`, `.github/workflows/ci.yml` | README 60-sec & cited; thread findings-first; CI defined | no |
| 4.3 | Debt + audits | `CLAUDE.md` rewrite, `ros_forgery.txt` header, real fuzz run + `fuzz/README.md`, `deny`/`audit` re-verify | debts closed; fuzz/audit evidence honest | **yes** (else fallback) |
| 4.4 | Final DoD audit | `docs/specs/dod-audit.md` mapping every DoD item to evidence | every code row green; owner gate noted | no |

**Session 4.1 prompt**
> Read `phase4-spec.md` §2, §4, §5. Execute **Session 4.1 only**: add dev-deps `ed25519-dalek` and `bs58` (verify they stay dev-only via `cargo tree -e normal`). Write `examples/in_process_2of3.rs` (3-party Pedersen DKG over `mpsc` channels → 2-of-3 FROST sign → verify → print group key + "verified", stdout only, <~120 lines) and `examples/solana_compat.rs` (FROST sign → verify with `ed25519-dalek` as an INDEPENDENT verifier, documenting the exact verify variant that accepts it; print `bs58` Solana address; include the proven/not-proven comment block; no SDK/RPC/broadcast). Touch no frozen module. Both `cargo run --example` must succeed. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 4.2 prompt**
> Read `phase4-spec.md` §6, §7, §8. Execute **Session 4.2 only**: rewrite `README.md` as a systems-crypto primitive per §6 (60-second grasp, no app glue, the honest audit-then-rebuild origin story, every quantitative claim citing its committed file, the one-line flagship mapping). Write `docs/x-thread.md` per §7 (findings-first, lead with the ~49 ms forgery, every claim cites a file, no marketing, no ask). Add `.github/workflows/ci.yml` (build + clippy -D + test with fuzz excluded + cargo deny + cargo audit, pinned stable toolchain). Touch no source. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 4.3 prompt**
> Read `phase4-spec.md` §3. Prereq (human, §0): `rustup toolchain install nightly`, `sudo apt-get install -y clang`, `cargo install cargo-fuzz cargo-deny cargo-audit`. Execute **Session 4.3 only**: rewrite `CLAUDE.md` (Appendix A, current across all phases); add the benchmark-variance header to `legacy/results/ros_forgery.txt`; if the fuzz tooling is present, run each of the six targets under libFuzzer for a committed budget and update `fuzz/README.md` with the real per-target exec count + wall-time + 0 crashes (if absent, leave the bounded floor and note the coverage-guided run is pending local execution); re-run `cargo deny check` and `cargo audit` from the installed binaries, confirm clean, and record the `atomic-polyfill` lockfile-orphan decision (leave documented, no blanket `cargo update`). Touch no source module. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 4.4 prompt**
> Read `phase4-spec.md` §9. Execute **Session 4.4 only**: write `docs/specs/dod-audit.md` mapping every `kickoff-brief.md` §6 item (1–11) and every `kickoff-amendment-1.md` addition to its committed evidence file, with a green/owner-gate status per row. Confirm `cargo tree -e normal -p frost-core` is the six crates and `#![forbid(unsafe_code)]` is intact. Touch no source. Commit, run build + clippy -D warnings + test, report the audit table, and STOP — flag that distribution is authorized only after the owner clears the §9 item-11 comprehension gate. Phase 4 complete.
