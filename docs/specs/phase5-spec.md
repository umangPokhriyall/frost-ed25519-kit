# frost-ed25519-kit — Phase 5 Specification: Distribution Readiness & Honest Documentation of the Fuzz Finding

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0–4-spec.md`, and the current `CLAUDE.md`. Read all first.
**This is the complete, authoritative Phase 5 spec.** The primitive is engineering-complete and sound (Phase 4 DoD code-rows all green). Phase 5 changes **no shipped logic**. It does three things: document the Phase 4 fuzz finding for the signal it is, reconcile the prose so every claim is precise and evidenced, and stage the human-only gates that authorize distribution. It also updates the portfolio ledger so the macro strategy stays coherent.
**Audience:** Claude Code for the documentation sessions (§3–§5); the human for the distribution gates (§6), which no session can clear.

---

## 0. Why this phase exists

The brief's plan ended at Phase 4, and the engineering did too. Two things make a short Phase 5 not scope-creep but completion:

1. **A material event arrived after the docs were written.** The coverage-guided fuzz run found a real non-canonical point-encoding acceptance in the frozen `group.rs` — a signature/point malleability vector — which was authorized, fixed (RFC 8032 strict decoding), regression-pinned, and re-fuzzed clean. The README/THREAT-MODEL prose was committed in Session 4.2, *before* the 4.3 fix. The text is accurate now, but it documents intent-ahead-of-behavior, and — more importantly — **the finding itself is the strongest credibility artifact in the repo and is currently buried in a session log.** Telling it accurately is in-scope completion, not new work.
2. **Distribution was staged, not executed.** NORTH-STAR §7: distribution is half the value. The thread is drafted, CI is committed-but-never-run, the repo is unrenamed, and the portfolio ledger still marks Repo 4 pending. The last mile is unwalked.

### 0.1 Frozen / reused
- **All `frost-core` and `legacy` source is frozen, including the Phase 4 strict-decoding fix.** Phase 5 touches documentation, the portfolio ledger, and (optionally) the committed fuzz numbers. No source logic changes. If a doc reconciliation appears to require a code change, the code is already correct and the doc is wrong — fix the doc.

---

## 1. The honesty principle for this phase

The fuzz finding is documented as what it was: a real defect, in a frozen module, that the random-input floor missed and the coverage-guided run caught in seconds. **Do not soften it into "hardening" or "an improvement."** The value is precisely that it was a genuine bug found by the author's own tooling and fixed transparently. Equally: **do not inflate it** — it was a deserialization malleability vector (two byte-strings decoding to one point), not a key-recovery or forgery break. State the exact severity, the exact fix, and the exact evidence. The number does the work; the adjectives stay home.

---

## 2. Workspace additions (documentation + ledger only)

```
docs/THREAT-MODEL.md                 # UPDATE — add canonical-encoding enforcement + the finding
docs/ARCHITECTURE.md                 # UPDATE — record the authorized post-freeze fix as a decision
README.md                            # UPDATE — precise wording; one line on the finding
docs/x-thread.md                     # UPDATE — add the fuzz-found-and-fixed beat
fuzz/README.md                       # UPDATE (optional, §4) — longer soak numbers if run
docs/specs/comprehension-checklist.md# NEW — the owner's self-exam (questions only, no answers)
STATE.md                             # UPDATE — portfolio ledger: Repo 4 → complete (portfolio root, §5)
```

No source files, no dependency changes. `cargo tree -e normal -p frost-core` stays the six crates; this is invariant and re-confirmed at phase end out of habit.

---

## 3. Document the finding and reconcile the prose (the core of Phase 5)

### 3.1 `docs/THREAT-MODEL.md` — canonical-encoding enforcement
Add (or expand) a section on **input-encoding canonicality** alongside the existing cofactor/small-subgroup material:
- The invariant: every point and scalar crossing the trust boundary must be the *canonical* encoding; non-canonical encodings are rejected, never coerced. Cite the implementation (`group.rs` strict decoding: re-encode the decompressed point and reject on any byte mismatch, before the torsion check) and the regression tests (`tests/adversarial.rs`, the two pinned crashing inputs).
- The vector it closes: a non-canonical `y ≥ p` or a set sign bit on the `x = 0` point decoding to the same group element as a canonical encoding — point/signature malleability (two distinct byte-strings verifying as the same signature), directly relevant to the Ed25519/Solana positioning.
- How it was found: the coverage-guided fuzz run (`fuzz/`) caught it where the random-input floor did not — name this honestly as the reason the project mandated a coverage-guided pass.

### 3.2 `docs/ARCHITECTURE.md` — the authorized post-freeze fix as a decision
Record, in the decisions/rejected-alternatives area, the one authorized exception to the freeze:
- `group.rs` was frozen at Phase 0; the strict-decoding fix was an **owner-authorized** post-freeze change, made because the freeze contract's "STOP and ask" path was followed exactly — the agent surfaced the finding and did not edit the frozen module without authorization.
- State the design point: strict decoding (re-encode-and-compare) over trusting the curve library's `decompress`, because dalek's `decompress` silently canonicalizes non-canonical `y`. This is the canonical-encoding analogue of the project's "reject, never coerce" rule.
- Confirm RFC 9591 conformance is unaffected (the differential and KAT suites pass post-fix — canonical vectors are unchanged by a stricter rejection of non-canonical inputs).

### 3.3 `README.md` — precise wording + one line on the finding
- Make the security-properties bullet on validated deserialization specific: "constant-time validated deserialization with **strict canonical-encoding enforcement** (non-canonical scalars and points rejected, never coerced — `group.rs`, `tests/adversarial.rs`), cofactor/small-subgroup checks."
- Add one honest line to the origin story or the security section: the coverage-guided fuzzer found a non-canonical point-encoding malleability vector in the core, which was fixed with RFC 8032 strict decoding and regression-pinned (`fuzz/README.md`). This *strengthens* the audit-then-rebuild narrative — the methodology caught a bug in the author's own frozen code.
- Keep the writing standard: no adjective the evidence has not earned; every claim cites a file.

### 3.4 `docs/x-thread.md` — add the fuzz beat
Insert one tweet (between the rebuild/DKG beats and the surface/close beats): the coverage-guided fuzzer found a point-malleability bug the random floor missed, fixed via strict decoding, regression-pinned — the methodology working on the author's own code. This is the most honest, most senior beat in the thread; it is findings-first by definition. Every claim still cites a committed file; no marketing; no ask.

### 3.5 Cross-check the whole prose surface for intent-ahead-of-behavior
The 4.2-before-4.3 sequencing means the docs must be swept once: every present-tense security claim in README, THREAT-MODEL, and ARCHITECTURE is verified against the *current* committed code, and any claim that describes intent rather than committed behavior is corrected to match the code. State in the session report which claims were checked.

---

## 4. Optional: a longer fuzz soak (tooling already installed)

The Phase 4 run was 60 s/target (104,624,899 execs total) and found the bug in seconds — the deserializers are shallow, so returns diminish. Still, since `cargo-fuzz` is now installed, a one-time longer soak (e.g. 30–60 min/target, or until coverage plateaus) converts "I fuzzed each deserializer for a minute" into "for an hour," which forecloses the "did you really fuzz it" question for a security primitive. If run, update `fuzz/README.md` with the real per-target exec counts, wall-time, and `0 crashes`, reported as measured. **This is optional; if skipped, the Phase 4 numbers stand and the README says the soak budget plainly.** Do not claim a soak that was not run.

---

## 5. Portfolio ledger — `STATE.md` (portfolio root, not the repo)

`STATE.md` lives at the orchestration root, above the repo. If Claude Code's session is repo-scoped, this is applied at the portfolio level (a separate session or a manual edit); the content is specified here so it is built from committed facts either way.

Update the project ledger row for Repo 4 to **✅ Complete**, and add a completed-state record mirroring the Rust-Tcp-Server §2 format, built only from committed numbers:
- **What it is:** a hand-rolled FROST-Ed25519 (RFC 9591) threshold-signature primitive — sans-IO, `#![forbid(unsafe_code)]`, six shipped dependencies.
- **Headline telemetry (each citing its file):** RFC 9591 KATs pass byte-for-byte, intermediates-first (`tests/rfc9591_kat.rs`); 10,000-case differential vs `frost-ed25519`, `2 ≤ t ≤ n ≤ 8`, byte-identical (`tests/differential.rs`); ROS forgery against the archived legacy scheme in ~49 ms at ℓ=256 (`legacy/results/ros_forgery.txt`), FROST returns `NoSolution` (`tests/ros_resistance.rs`); Pedersen DKG with rogue-key PoK, identifiable abort (`dkg.rs`, `tests/dkg_*`); coverage-guided fuzzing across six deserializers (104M+ execs) that found and closed a non-canonical point-malleability vector (`fuzz/README.md`, `group.rs`).
- **Key decisions carried forward:** hand-roll-plus-differential-oracle over wholesale crate use; Pedersen DKG over trusted dealer (trusted dealer retained, documented); abort-and-identify over robust GJKR; strict canonical-encoding enforcement.
- **Synergy to the flagship:** secret hygiene (split trust, zeroize-after-use, validated handling, identifiable abort) for secrets transiting the microVM agent sandbox.
- **Distribution status:** set to the true state (drafted / posted) — do not mark posted until it is.

---

## 6. The human-only distribution gates (no session can clear these)

These are stated so the gate is explicit, not so Claude Code executes them. Distribution is authorized only when all are cleared:

1. **Comprehension gate (NORTH-STAR §4, DoD item 11).** The owner re-derives, from memory: the FROST partial `z_i = d_i + ρ_i e_i + λ_i c s_i`; why `ρ_i = H1(group_public ‖ msg ‖ commitment_list ‖ id)` denies the ROS solver its linear system where plain `R = ΣR_i` does not; and the DKG PoK check `μ_i·G == R_i + c_i·φ_{i,0}` and why it stops rogue-key biasing. Use `docs/specs/comprehension-checklist.md` (§7) as the self-exam. If any cannot be derived unaided, the gate is not cleared — that is the signal the layer is not yet owned, and it must be closed before the next repo or the flagship builds on it.
2. **CI observed green.** Push and confirm `.github/workflows/ci.yml` actually passes on a GitHub runner. CI is committed but has never run; "CI green" in the DoD is claimed-by-construction until observed. A YAML or action-version error surfaces only here.
3. **Tooling/installs done** (`phase4-spec.md` §0): `sudo apt-get install -y clang`, the `cargo install` set, and — if renaming — `gh auth login` + `gh repo rename frost-ed25519-kit`. The rename sharpens the positioning (the slug stops reading as an app); GitHub keeps a redirect.
4. **Then distribute** (NORTH-STAR §7): lead with the link, post findings not hype, engage technically. The thread is the opener; the repo is the proof.

---

## 7. `docs/specs/comprehension-checklist.md` — the owner's self-exam (questions only)

A Claude Code deliverable, but **questions without answers** — it operationalizes the gate without becoming an answer key to memorize (which would defeat re-derivation from memory). The questions, at minimum:
1. Derive the FROST partial signature `z_i` from scratch. What is each term and why is it there?
2. Why does the binding factor defeat the ROS attack? Construct the solver's linear system for the naive scheme, then show why it has no analogue under FROST.
3. What exactly does the DKG proof of knowledge prove, and which attack does it stop? Write the verification equation and explain a rogue-key attack it prevents.
4. Why is reconstruction from `t-1` shares information-theoretically impossible, and what changes at `t`?
5. Why is strict canonical-encoding enforcement necessary — what malleability does non-canonical acceptance permit, and how did the fuzzer find it?
6. What can a malicious aggregator do, and what can it provably not do?
7. What is the DKG's transport trust assumption, and why does VSS force it?

The header states: these are answered **from memory, unaided**; the file holds no answers by design.

---

## 8. Phase 5 Definition of Done

1. No `frost-core`/`legacy` source change (`git diff` confirms); shipped graph still six crates.
2. `THREAT-MODEL.md` documents canonical-encoding enforcement, the malleability vector, the fix, and that the coverage-guided fuzzer found it (§3.1).
3. `ARCHITECTURE.md` records the authorized post-freeze `group.rs` fix as a decision, with the strict-decoding rationale and the RFC-conformance confirmation (§3.2).
4. `README.md` wording is precise on strict canonical-encoding enforcement and carries the one honest line on the finding (§3.3); every claim cites a file.
5. `docs/x-thread.md` includes the fuzz-found-and-fixed beat, findings-first, cited (§3.4).
6. The full prose surface is swept for intent-ahead-of-behavior; the session report lists what was checked (§3.5).
7. `docs/specs/comprehension-checklist.md` exists as questions-only (§7).
8. `STATE.md` updated to Repo 4 → complete with the committed-fact telemetry (§5), at the portfolio level.
9. (Optional) `fuzz/README.md` carries longer-soak numbers if a soak was run; otherwise the Phase 4 numbers stand with the budget stated (§4).
10. `cargo build`, `cargo clippy --all-targets -D warnings`, `cargo test --workspace` clean (sanity; no source changed).
11. The §6 human gates are restated in the session report as the remaining, owner-only path to distribution — none claimed as cleared by Claude Code.

---

## Appendix A — `CLAUDE.md` note for Phase 5

```markdown
## Hard rules (Phase 5 additions)
20. Phase 5 changes NO shipped logic. Docs, ledger, and committed fuzz numbers only.
21. The fuzz finding is documented as a real bug found by coverage-guided fuzzing and fixed
    transparently — neither softened to "hardening" nor inflated beyond a deserialization
    malleability vector. State exact severity, exact fix, exact evidence file.
22. Every present-tense security claim in README/THREAT-MODEL/ARCHITECTURE is verified against
    CURRENT committed code; intent-ahead-of-behavior claims are corrected to match the code.
23. The comprehension checklist holds questions only — no answers. The gate is re-derivation
    from memory; an answer key would defeat it.
24. Distribution gates (comprehension, observed CI green, rename, post) are HUMAN-ONLY; no
    session marks them cleared.
```

## Appendix B — Claude Code execution plan (Phase 5)

| # | Session | Deliverable | Done when | Needs tooling? |
|---|---|---|---|---|
| 5.1 | Document the finding + reconcile prose | THREAT-MODEL, ARCHITECTURE, README, x-thread updates; full prose sweep | finding documented honestly; all claims verified against current code | no |
| 5.2 | Checklist + ledger + optional soak | `comprehension-checklist.md` (questions only); `STATE.md` Repo 4 → complete; optional fuzz soak | checklist + ledger committed; soak numbers honest if run | soak only |

**Session 5.1 prompt**
> Read `phase5-spec.md` §1, §3. Execute **Session 5.1 only**: update `docs/THREAT-MODEL.md` (canonical-encoding enforcement, the malleability vector, the strict-decoding fix, and that the coverage-guided fuzzer found what the random floor missed), `docs/ARCHITECTURE.md` (the authorized post-freeze `group.rs` fix as a decision, with rationale and RFC-conformance confirmation), `README.md` (precise strict-encoding wording + one honest line on the finding), and `docs/x-thread.md` (add the fuzz-found-and-fixed beat). Then sweep every present-tense security claim across the three docs against the current committed code and correct any intent-ahead-of-behavior wording. Document the finding honestly — not softened, not inflated; exact severity, fix, and evidence file. Touch no source. Commit, run build + clippy -D warnings + test (sanity), report which claims were checked, STOP.

**Session 5.2 prompt**
> Read `phase5-spec.md` §4, §5, §7. Execute **Session 5.2 only**: write `docs/specs/comprehension-checklist.md` as questions only (no answers, header stating answered-from-memory-unaided); update `STATE.md` at the portfolio root to mark Repo 4 complete with the committed-fact telemetry per §5 (each claim citing its file; distribution status set to the true state). Optionally, if `cargo-fuzz` is installed, run a longer soak (30–60 min/target) and update `fuzz/README.md` with the real measured numbers; if not run, leave the Phase 4 numbers and state the budget. Touch no source. Commit, run build + clippy -D warnings + test (sanity), restate the §6 human-only distribution gates in the report, STOP. Phase 5 complete — distribution remains owner-gated.
```
