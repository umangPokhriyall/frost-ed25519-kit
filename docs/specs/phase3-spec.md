# frost-ed25519-kit — Phase 3 Specification: Adversarial Hardening, the ROS Forgery, and the Threat Model

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0/1/2-spec.md`, and the current `CLAUDE.md`. Read all first.
**This is the complete, authoritative Phase 3 spec.** It covers the polynomial-time ROS forgery against the archived `legacy/` oracle (amendment §1 — the headline artifact), the self-explaining FROST negative control, the consolidated adversarial audit with cross-session replay, deserializer fuzzing, the supply-chain audit (`cargo audit` + `cargo deny`), the zeroization audit, and the two prose deliverables: `THREAT-MODEL.md` and `ARCHITECTURE.md` (the latter closing the Phase 2 §9.8 debt).
**Audience:** Claude Code. Authoritative.

---

## 1. Phase 3 in one paragraph

Demonstrate, with a committed number, that the construction this repo used to ship is forgeable in milliseconds — and that FROST is not. Implement the Benhamouda–Lefranc–Loss–Orsini–Raykova (2020) polynomial-time ROS solver against the archived `legacy/` single-key Schnorr oracle, producing a signature on a message **no honest session ever signed**, verifying under the standard equation. Run the *same* solver against a FROST signing oracle and show it cannot construct the forgery — with a doc-comment that states *why* (the binding factor denies the solver its linear system), because a negative control that does not explain itself proves nothing. Then consolidate the adversarial surface into one audited suite (adding the cross-session replay case the binding factor defeats), fuzz every deserializer, lock the supply chain, audit secret hygiene, and write the two documents that let a Principal Security Engineer reconstruct the trust model without reading the code. No shipped-crate logic changes this phase — everything frozen stays frozen; the work is attacks, tests, audits, and prose.

### 1.1 Frozen / reused
- **Everything in `frost-core` is frozen:** `group`, `secret`, `message`, `vss`, `keygen`, `sign`, `verify`, `dkg`, `ciphersuite`, `error`. Phase 3 adds no shipped logic. If an attack or audit appears to require a core change, the design is wrong — STOP and ask. (A *documentation* string or a `#[cfg(test)]` helper is not a logic change.)
- **`legacy/` is the attack target and now also houses the solver.** Its oracle (Session 1.5) is reused unchanged; the ROS solver is added as `legacy/src/ros.rs`. `legacy` stays `publish = false` and **test-only** — never in `frost-core`'s shipped graph (re-asserted in DoD).
- **The frozen Phase 1 signing path is the FROST negative-control target**, driven through its public API only.

---

## 2. Workspace additions & dependencies

```
legacy/src/ros.rs                      # NEW — the BLLOR polynomial-time ROS solver (attacks the oracle API only)
legacy/results/ros_forgery.txt         # NEW — committed artifact: ℓ, wall-clock, out-of-set proof
frost-core/tests/ros_resistance.rs     # NEW — solver vs legacy (forges) + solver vs FROST (no solution) + the argument
frost-core/tests/adversarial.rs        # NEW — consolidated adversarial audit + cross-session replay
fuzz/                                   # NEW — cargo-fuzz crate; one target per deserializer
deny.toml                              # NEW — supply-chain policy (bans, licenses, sources)
docs/THREAT-MODEL.md                   # NEW — trust boundaries, adversary model, defenses, out-of-scope
docs/ARCHITECTURE.md                   # NEW — sans-IO boundary, rejected-alternatives table, secret-in-transit (closes P2 §9.8)
```

Dependency additions (all dev/tooling only — shipped graph stays `curve25519-dalek, rand_core, sha2, subtle, thiserror, zeroize`):
```toml
# frost-core dev-dependencies:
legacy = { path = "../legacy" }   # ROS resistance test only — test-only, never shipped
# fuzz/ crate (separate, not part of the shipped workspace members for `cargo build`):
libfuzzer-sys = "0.4"
# tooling (not dependencies): cargo-audit, cargo-deny (invoked, not linked)
```
Re-verify at phase end: `cargo tree -e normal -p frost-core` is unchanged; `legacy`, `libfuzzer-sys` absent from it.

---

## 3. The ROS forgery (amendment §1 — the headline artifact)

### 3.1 What is being proven, and the falsifiable gate
The legacy oracle is single-key concurrent Schnorr (Session 1.5): `open_session() → R_i = r_i·G`, `sign(i, m) → z_i = r_i + H(R_i ‖ X ‖ m)·s`, unlimited concurrent open sessions, **no binding factor**. The threshold scheme reduces to this (the Session 1.5 doc-comment). The ROS attack forges a signature on a fresh message *without the secret*.

**The success criterion is the correctness oracle — and the strawman guard.** A result counts as a forgery only if **both** hold:
1. the produced `(R*, z*)` **verifies** under the standard equation `[8]·z*·G == [8]·(R* + H(R* ‖ X ‖ m*)·X)` (reuse `legacy`'s free `verify`), and
2. `m*` is **provably outside** the signed set — assert `m* ∉ {m_1, …, m_ℓ}` in code.

A "forgery" that fails (1) or violates (2) is a strawman and a **STOP**, not a pass. The solver receives **only** the public key `X` and the oracle handle — never `s`; assert this at the type level so a forgery cannot secretly use the secret.

### 3.2 The solver (`legacy/src/ros.rs`)
Implement the **BLLOR 2020 polynomial-time construction**, not an invented variant. **Verify the construction against the paper "On the (in)security of ROS" (Benhamouda et al., EUROCRYPT 2021 / ePrint 2020/945) and, if available, a reference PoC, before writing the body** — the same verify-never-assume discipline that caught the rho prefix. Operationally, per amendment §1:
- Open `ℓ` concurrent sessions where `ℓ ≥ 253` (one per bit of the ~2^252 edwards25519 order); **use `ℓ = 256`** for slack. Collect `R_1 … R_ℓ`.
- Construct the forged aggregate commitment as the fixed public combination of the `R_i`, and the forged challenge `c*` for the chosen target message `m*` as a **known linear combination of the per-session challenges** — which the adversary forces by **choosing each session's message after seeing all `R_i`** (the binary-decomposition trick).
- Close the sessions (`sign` each with the chosen `m_i`), aggregate `(R*, z*)`, and check §3.1.

The solver exposes a clean API so the negative control can reuse it:
```rust
pub trait SchnorrLikeOracle { /* open_session() -> (SessionId, R_i); sign(SessionId, &[u8]) -> z_i; public_key() -> X */ }
pub enum RosOutcome { Forged { sig, m_star, sessions: usize, elapsed: Duration }, NoSolution }
pub fn ros_attack<O: SchnorrLikeOracle>(oracle: &mut O, ell: usize, target: &[u8]) -> RosOutcome;
```

### 3.3 The committed artifact
On success, write `legacy/results/ros_forgery.txt`: `ℓ`, wall-clock to forge, the target `m*`, and an explicit line proving `m* ∉ {m_i}`. Bench-style, one line: `ℓ=256 sessions, forgery in {X} ms`. **A forgery in milliseconds against the construction the repo used to ship is the single most senior artifact in the portfolio** — it is the numeric, falsifiable proof that the rebuild was necessary.

### 3.4 The negative control that explains itself (`ros_resistance.rs`)
Run the *same* `ros_attack` against a FROST signing oracle (a thin `SchnorrLikeOracle`-shaped adapter over the frozen Phase 1 `commit`/`sign`/`aggregate`, single-signer or threshold). It must return `RosOutcome::NoSolution` — the solver reaches the step where it must express `c*` as a fixed linear combination of per-session challenges and **finds no solution exists**, because each FROST challenge depends on the group commitment `R = Σ(D_j + ρ_j·E_j)` with binding factor `ρ_j = H1(group_public ‖ msg_hash ‖ com_hash ‖ id)` — a function of the message and the full commitment list. The per-session challenge is therefore not determined until the messages are fixed, so the linear system the solver requires never exists. **Assert `NoSolution`, not merely "no verifying forgery in N tries"** — a failed-attempt count proves nothing; the structural unsolvability is the proof. The module doc-comment carries this argument in full; the self-audit gate (§8 DoD) tests the owner can reproduce it from memory.

---

## 4. Consolidated adversarial audit (`tests/adversarial.rs`)

Phases 0–2 already prove, in their own suites: non-canonical scalar rejection, low-order/non-prime-order point rejection (group layer), zero/duplicate identifier rejection, bad signing partial → `Culprit`, bad DKG PoK/share/rogue-key → `Culprit`. **Phase 3 does not delete those.** It adds one consolidated, audit-oriented suite that a reviewer can read as the single threat-surface index, intentionally re-exercising the cross-cutting invariants in one place (defense-in-depth, one entry point) **plus the genuinely new cases:**

- **Cross-session replay (the new case, and it pays off the ROS theme):** a `SignatureShare` valid in session A is injected into session B (different message and/or commitment set); `aggregate`/`verify_share` rejects it (`Culprit` or verification failure), because the recomputed binding factor and challenge bind the partial to A's exact `(msg, commitment-set)`. This demonstrates the binding factor's anti-replay property — the same mechanism that defeats ROS defeats replay.
- **Type-level nonce single-use** is a compile-time guarantee (`SigningNonces` consumed by value); add a `trybuild`-style note or a comment-documented compile-fail demonstrating reuse does not compile (do not weaken the type to test it at runtime).
- **Wrong-index / wrong-cosigner-set share** (re-exercised through the consolidated entry): `Culprit`.
- **Malformed wire bytes** into every public `from_bytes`/deserialize: `Err`, never panic (the fuzz targets in §5 are the exhaustive version; this suite pins a few named regressions).

Header notes which invariants are primarily owned by earlier suites and which are new here, so the overlap is documented, not accidental.

---

## 5. Fuzzing (`fuzz/`)

A `cargo-fuzz` crate with one `libfuzzer-sys` target per public deserializer:
`GScalar::from_canonical_bytes`, `GElement::from_compressed`, `Identifier::from_canonical_bytes`, `Signature::from_bytes`, `SigningCommitments` deser, `SignatureShare` deser, `round1::Package` deser, `round2::Package` deser.

**Invariant for every target:** arbitrary input either returns `Ok` with a value that re-serializes to the *same canonical bytes* (round-trip stability) or returns `Err` — **never panics, never accepts a non-canonical encoding, never accepts a non-prime-order point.** Commit a seed corpus.

**Honesty (measure-never-guess applies to fuzzing too):** absence of a crash within a budget is not proof of total absence. Commit the budget actually run (e.g. exec count or wall-time per target) in `fuzz/README.md`; report it as "N execs, 0 crashes," not "fuzzed, clean." CI runs a short bounded pass; longer runs are local. `cargo-fuzz` needs a nightly toolchain and is its own crate — it is **not** a member of the `cargo build`/`clippy -D warnings` workspace gate, so the shipped build stays stable; note this in `fuzz/README.md`.

---

## 6. Supply chain (`deny.toml`) and zeroization audit

### 6.1 `cargo audit` + `cargo deny`
- `cargo audit`: zero open RUSTSEC advisories in the shipped graph.
- `deny.toml`: an allowlist enforcing the shipped dependency set (`curve25519-dalek, rand_core, sha2, subtle, thiserror, zeroize`), banning anything else from the normal graph; a license policy; a single-source policy (crates.io only). `cargo deny check` clean.
- The signal is the *tiny* surface: a threshold-signature primitive with six audited shipped dependencies and `#![forbid(unsafe_code)]` is itself a security argument. State the count in `ARCHITECTURE.md`.

### 6.2 Zeroization audit — and its honest limit
- A structural test asserting every secret type (`SigningShare`, `SigningNonces`, the DKG `round1`/`round2` `SecretPackage`s, `round2::Package`, `SecretPolynomial`) is `ZeroizeOnDrop`, has a **redacting `Debug`** (a test asserts the formatted string contains no key bytes), and does **not** implement `Serialize` — except `round2::Package`, whose serialize-for-private-transport exception is documented (§7 of Phase 2; recorded in the threat model here).
- **Honest limit, stated in `THREAT-MODEL.md`:** true post-free memory verification requires inspecting freed memory, which needs `unsafe` — and the crate is `#![forbid(unsafe_code)]`. The audit therefore proves the *types and traits* are correct (zeroize-on-drop is wired, no secret is `Debug`/`Serialize`-leaked), not that a specific freed page is scrubbed. Name this boundary rather than imply a guarantee the test does not provide.

---

## 7. The prose deliverables

### 7.1 `docs/THREAT-MODEL.md`
The document a Principal Security Engineer reads first. Sections:
- **Trust boundaries.** Who holds what; the dealer/coordinator/aggregator roles and what each sees.
- **Adversary model & the sub-threshold guarantee.** A coalition of `< t` participants learns **nothing** about the group secret (information-theoretic below threshold — the Shamir property, exercised by the Phase 0 `t-1`-reveals-nothing test). At `≥ t`, reconstruction is by design — state it plainly; this is not a vulnerability, it is the threshold.
- **Aggregator trust.** The aggregator sees commitments and partials but no shares; it cannot extract `s_i` from `z_i = d_i + ρ_i e_i + λ_i c s_i` without the nonces. State what a malicious aggregator *can* do (refuse to aggregate, mis-attribute — bounded by identifiable abort naming the real culprit) and *cannot* (forge, learn the key).
- **The ROS / concurrent-signing defense.** The headline: cross-reference the Phase 3 forgery artifact (`legacy/results/ros_forgery.txt`) as the evidence that the naive scheme is broken, and the binding factor as the fix. One paragraph, with the structural argument.
- **Rogue-key resistance.** The DKG proof of knowledge; the Gennaro et al. biasing attack it defeats.
- **Small-subgroup / cofactor.** The group layer rejects non-prime-order points; why that matters for Ed25519's cofactor 8.
- **Hedged nonces.** `H3(random ‖ secret)`; one sentence; the PS3 nonce-reuse failure as the cautionary reference.
- **Identifiable abort.** Bad partial / bad PoK / bad share name the culprit; the flagship secret-broker mapping (know *which* component failed).
- **DKG transport assumption (closes part of P2 §9.8).** `round2` shares are secret-in-transit and **require a private, authenticated channel**; the library provides the share type's hygiene (zeroize, redacting Debug) but **not** the channel — that is the integrator's responsibility. State it as an explicit assumption.
- **Out of scope.** No robust/restartable DKG (abort-and-identify only); no transport security provided by the library; no side-channel hardening beyond `curve25519-dalek`'s constant-time arithmetic; no defense against a `≥ t` collusion (definitional); the fuzzing/zeroization honesty limits (§5, §6.2).

### 7.2 `docs/ARCHITECTURE.md` (closes the rest of P2 §9.8)
- **The sans-IO boundary.** The core is pure functions + state machines; no I/O in the trust path; the same discipline that froze the TCP `core`.
- **Module map.** Frozen core (`group`/`secret`/`message`/`vss`/`keygen`/`sign`/`verify`/`dkg`/`ciphersuite`/`error`); `legacy/` (attack target + solver, test-only); the six-dependency shipped graph; `#![forbid(unsafe_code)]`.
- **Secret-in-transit recording (the explicit P2 §9.8 closure).** `round2::Package` is serializable-but-secret, zeroize-on-drop, redacting Debug, private+authenticated-channel-only — the one principled deviation from "no Serialize on secrets," and why VSS forces it.
- **Rejected-alternatives table** (each row: choice / rejected option / why), now substantiated by Phase 3 evidence:
  - naive threshold Schnorr → rejected → *forgeable in milliseconds* (cite the artifact); FROST's binding factor is the fix.
  - `frost-ed25519` wholesale → rejected as the shipped impl → hand-roll is the signal; the crate is the differential oracle (the KAT + interop are why hand-rolling is safe).
  - trusted dealer → retained as documented fallback → Pedersen DKG is the default for no-trusted-dealer keygen.
  - robust GJKR complaint-and-continue → rejected → abort-and-identify matches the ecosystem oracle and preserves the differential gate (the brief's "complaint round" supersession).

---

## 8. Phase 3 Definition of Done

1. All `frost-core` modules byte-for-byte unchanged (`git diff` confirms); no shipped logic added. `legacy/` oracle unchanged; `legacy/src/ros.rs` added.
2. **ROS forgery against `legacy/` succeeds** per §3.1: `(R*, z*)` verifies under the standard equation AND `m*` is asserted outside the signed set; the solver never receives `s`. `legacy/results/ros_forgery.txt` committed with `ℓ`, wall-clock, and the out-of-set proof.
3. **FROST negative control returns `RosOutcome::NoSolution`** (not "no forgery in N tries"); the `ros_resistance.rs` doc-comment carries the binding-factor argument in full.
4. **Consolidated adversarial suite** green, including the new **cross-session replay** rejection; overlap with earlier suites documented in the header; nonce single-use remains a compile-time guarantee.
5. **Fuzz targets** for every public deserializer build and run a bounded pass with 0 crashes; round-trip/canonical/prime-order invariants hold; the budget run is committed in `fuzz/README.md` (reported as exec count, not "clean").
6. **`cargo audit` clean**; **`cargo deny check` clean** against a committed `deny.toml` enforcing the six-crate allowlist, license, and single-source policy.
7. **Zeroization audit** green: every secret type is `ZeroizeOnDrop`, redacting-`Debug` (asserted no key bytes), non-`Serialize` (except the documented `round2::Package`); the post-free-memory honest limit is stated in `THREAT-MODEL.md`.
8. **`docs/THREAT-MODEL.md`** complete per §7.1, including the DKG transport assumption and all out-of-scope items.
9. **`docs/ARCHITECTURE.md`** complete per §7.2, **closing the Phase 2 §9.8 debt** (secret-in-transit recording + rejected-alternatives table).
10. Shipped graph unchanged (`cargo tree -e normal -p frost-core` = the six crates); `legacy`/`libfuzzer-sys` dev/tooling-only; `#![forbid(unsafe_code)]` intact in all shipped crates.
11. `cargo build`, `cargo clippy --all-targets -D warnings`, `cargo test` clean workspace-wide (the `fuzz/` crate is excluded from this gate per §5; note it).
12. **Self-audit (comprehension gate):** the owner can, from memory, (a) walk the ROS attack end to end and (b) state precisely why `ρ_i = H1(… msg, B …)` makes the solver's linear system non-existent — the argument in `ros_resistance.rs`.

No README rewrite, no examples, no distribution this phase — those are Phase 4.

---

## Appendix A — `CLAUDE.md` update for Phase 3

```markdown
## Hard rules (Phase 3 additions)
15. ALL frost-core modules are FROZEN. Phase 3 adds attacks, tests, audits, and prose only —
    no shipped logic. legacy/ stays publish=false and TEST-ONLY (cargo tree -e normal proves it).
16. ROS forgery counts ONLY if (a) it verifies under the standard equation and (b) m* is asserted
    outside the signed set; the solver never receives the secret s. Implement the BLLOR 2020
    construction VERIFIED against the paper — not an invented variant. A non-verifying or
    in-set "forgery" is a STOP.
17. The FROST negative control asserts RosOutcome::NoSolution (structural), never a failed-attempt
    count. The ros_resistance.rs doc-comment carries the binding-factor argument in full.
18. Fuzzing and zeroization are reported HONESTLY: commit the fuzz budget (exec count, not "clean");
    state in THREAT-MODEL.md that post-free memory scrub is unverifiable under forbid(unsafe_code).
19. ARCHITECTURE.md closes the P2 §9.8 secret-in-transit debt; THREAT-MODEL.md states every
    out-of-scope assumption (no robust DKG, no transport security, no side-channel hardening).
```

## Appendix B — Claude Code execution plan (Phase 3)

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 3.1 | ROS forgery + resistance | `legacy/src/ros.rs` (BLLOR solver, verified), `legacy/results/ros_forgery.txt`, `frost-core/tests/ros_resistance.rs` (forge vs legacy; `NoSolution` vs FROST; argument) | forgery verifies & m* out-of-set; FROST → `NoSolution`; artifact committed |
| 3.2 | Adversarial + fuzz | `tests/adversarial.rs` (consolidated + cross-session replay), `fuzz/` (one target per deserializer + corpus + README budget) | replay rejected; fuzz bounded pass 0 crashes; budget committed |
| 3.3 | Supply chain + audit + prose | `deny.toml`, zeroization audit test, `docs/THREAT-MODEL.md`, `docs/ARCHITECTURE.md` (closes §9.8); DoD verify | audits clean; both docs complete; DoD §8 verified item by item |

**Session 3.1 prompt**
> Read `phase3-spec.md` §1–§3 and `kickoff-amendment-1.md` §1. Execute **Session 3.1 only**: verify the BLLOR 2020 ROS construction against the paper, then implement `legacy/src/ros.rs` — `ros_attack` over a `SchnorrLikeOracle` (`ℓ=256`), receiving only `X` and the oracle handle, never the secret. Mount it against the `legacy/` oracle; on success write `legacy/results/ros_forgery.txt` (ℓ, wall-clock, m*, and the `m* ∉ {m_i}` proof). Write `frost-core/tests/ros_resistance.rs` with `legacy` as a dev-dependency: the positive forge (must verify under the standard equation AND assert m* out-of-set) and the FROST negative control over a thin oracle adapter on the frozen `commit`/`sign`/`aggregate` (must return `RosOutcome::NoSolution`); the module doc-comment carries the binding-factor argument. Touch no frozen module. A non-verifying or in-set forgery is a STOP. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 3.2 prompt**
> Read `phase3-spec.md` §4–§5. Execute **Session 3.2 only**: write `tests/adversarial.rs` — the consolidated audit (header documenting overlap with earlier suites) plus the new cross-session replay rejection (a partial valid in session A rejected in session B) and the named malformed-bytes regressions. Create the `fuzz/` cargo-fuzz crate with one `libfuzzer-sys` target per public deserializer (§5), a seed corpus, and `fuzz/README.md` stating the toolchain, the workspace-gate exclusion, and the committed budget (exec count, not "clean"). The invariant: never panic, never accept non-canonical/non-prime-order. Touch no frozen module. Commit, run build + clippy -D warnings + test (fuzz excluded), list changes, STOP.

**Session 3.3 prompt**
> Read `phase3-spec.md` §6–§9. Execute **Session 3.3 only**: add `deny.toml` (six-crate allowlist, license, single-source) and confirm `cargo audit` + `cargo deny check` clean; add the zeroization structural-audit test (every secret type ZeroizeOnDrop, redacting Debug asserted clean, non-Serialize except documented `round2::Package`); write `docs/THREAT-MODEL.md` (§7.1, including the DKG transport assumption and the honest fuzz/zeroization limits) and `docs/ARCHITECTURE.md` (§7.2, closing the P2 §9.8 secret-in-transit debt + the rejected-alternatives table). Touch no frozen module. Commit, run build + clippy -D warnings + test, verify DoD §8 item by item, STOP. Phase 3 complete.
