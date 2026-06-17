# solana-mpc-kit → frost-ed25519-kit — Per-Chat Kickoff Brief & Execution Spec

**Repo:** https://github.com/umangPokhriyall/solana-mpc-kit
**Owner:** internet-native systems engineer, no formal industry pedigree, building falsifiable proof-of-work.
**This document is the complete spec.** The executing chat has no other context. Read it fully before writing code.

---

## 0. Why this repo exists (the strategic frame)

This is **Repo 4 of the 5-repo portfolio** that disassembles the eventual **microVM agent-sandbox flagship** into independently built and measured components. Its job in the portfolio is one thing: **the secret-hygiene primitive** — the discipline and the construction for handling key material that must never be held whole, never persist in plaintext, and never survive its use.

This is not a Solana wallet app. The deliverable is **a correct, standardized, hand-rolled FROST-Ed25519 threshold-signature library — sans-IO, validated against the RFC 9591 test vectors, with an explicit threat model and a proven defense against the attack the current code is vulnerable to.**

**Why this specific artifact neutralizes the lack of pedigree:**
1. **Test vectors are objective.** A signature that matches RFC 9591 byte-for-byte does not care what school the author went to. They are the crypto analogue of a committed p99 number.
2. **FROST *is* senior cryptographic knowledge.** Understanding *why* the per-signer binding factor exists — that it defeats the ROS/Drijvers concurrent-forgery attack the naive scheme falls to — is exactly what a Principal Security Engineer probes.
3. **The threat model proves you can reason about adversaries**, not just call a curve library — the single hardest thing to fake.
4. **It is the literal substrate of the target domain.** An agent sandbox that holds secrets on behalf of untrusted guests needs precisely this: split trust (no component holds a usable key), zeroized-after-use secret paths, and constant-time validated handling.

**Direct microVM mapping (state this in the README):** the threshold split = the sandbox secret-broker pattern (host control plane never holds a usable secret alone; one compromised component ≠ key compromise); the `Zeroizing` / constant-time / validated-deserialization discipline = how the host handles any secret transiting to a guest (API keys, signing keys, tokens — never plaintext-at-rest, scrubbed on drop, never leaked via `Debug`/logs); the sans-IO protocol core = the same testability boundary that made the TCP `core` frozen and reusable — the secret path is verifiable without standing up the distributed system.

---

## 1. Current-state audit (what is wrong, precisely)

The workspace has four members — `orchestrator`, `node`, `store`, `nodeDb` — wiring two HTTP servers (`poem`/`tokio`) and two Postgres databases (`diesel`) around a ~250-line cryptographic core. The README documents a working devnet flow. It does not work as a *threshold* system. The defects below are ordered by severity.

### 1.1 The threshold property is fictional (fatal, security)
`node` round2 returns the final secret share to the coordinator (`Round2Response.my_final_share = Some(final_share_hex)`), and `orchestrator::create_wallet` collects every one into `final_shares`. **The coordinator therefore sees ≥ t shares and can reconstruct the full private key and sign unilaterally.** The code admits this in a comment ("in production you must NOT return the final share"). An MPC system that hands the secret to the coordinator is not an MPC system.

### 1.2 The signing scheme is the broken pre-FROST construction (fatal, security)
Signing is naive interactive threshold Schnorr: one nonce per signer (`sign_commit` → `R_i = r_i·G`), `R = ΣR_i`, `c = H(R‖X‖m)`, `z_i = r_i + c·λ_i·s_i`, `z = Σz_i`. There is **no binding factor**. This construction is vulnerable to the **Drijvers et al. concurrent-session attack** — an instance of the **ROS problem**, broken in polynomial time by Benhamouda et al. (2020) given enough parallel signing sessions. The README's roadmap labels it "FROST-style." It is not FROST; it is the exact thing FROST was published to fix. **This is the headline cryptographic vulnerability and the reason the repo must be rebuilt, not patched.**

### 1.3 Secret material has no hygiene (severe, security)
- **Shares broadcast in plaintext through a central party.** round1 returns *all* shares for *all* recipient indices to the coordinator in cleartext hex; the coordinator forwards the full `all_round1` to every node. The private-channel assumption of verifiable secret sharing is violated end to end. The coordinator — and every node — sees enough to reconstruct.
- **`final_share_enc` stores plaintext.** The column name and the migration comment claim "encrypted hex"; the code writes `encode_scalar_hex(&total)` — the raw scalar. A `_enc` suffix on plaintext is a landmine.
- **No zeroization anywhere.** Nonces live in a plaintext `HashMap<Uuid, Scalar>` in process RAM; polynomial coefficients, shares, and nonces are never scrubbed. A memory dump leaks key material.
- **`nodeDb/.env` is committed to the repo** (`DATABASE_URL=postgres://postgres:postgres@…`). It is absent from `.gitignore` while the other three `.env` files are listed. In a project whose entire thesis is secret hygiene, this is disqualifying on sight.

### 1.4 No authentication, no input discipline (severe, correctness)
- **No authn/authz between any parties.** Anything that can reach a node's port can drive keygen, request nonces, and request shares. The `node_identity` table exists but is never used.
- **Panics on attacker-controlled input throughout:** `.expect("bad challenge hex")`, `try_into().expect("bad challenge length")`, `Uuid::parse_str(...).unwrap()`, `panic!("nonce not found")`, `panic!("signature verification failed")`. A malformed message from any peer aborts the handler. Maps directly to the TCP brief's "one bad client must never kill the server."
- **Silent non-canonical coercion:** `Scalar::from_canonical_bytes(b).unwrap_or_else(|| Scalar::from_bytes_mod_order(b))` accepts non-canonical encodings of partial signatures and challenges by silently reducing them — a malleability gap. Reject, never coerce.
- **No subgroup checks.** `decompress()` is `None`-checked (good) but decompressed commitment/nonce points from peers are never checked for prime-order-subgroup membership. Ed25519's cofactor 8 admits a low-order-point biasing attack on the aggregate.

### 1.5 Architecture is a distributed system masquerading as a primitive (severe, signal)
The cryptographic content is ~250 lines. Around it: two `poem`/`tokio` HTTP servers, `reqwest`, two `diesel`/Postgres schemas behind a global `Mutex<Store>` (serializing all DB access on one connection), `solana-sdk`/`solana-client`/`spl-token`/`spl-associated-token-account`/`bincode`/`base64` for devnet SPL transfers, and an absolute path `/home/umang/rust/mpc/store/migrations` in `diesel.toml` that leaks the local username and breaks portability. **None of this is the primitive.** A Principal Security Engineer reviewing a threshold-signature crate does not care about devnet SPL transfers; the application glue dilutes the only signal that matters and *introduces* the plaintext-share-over-HTTP vulnerability.

### 1.6 Zero tests (cardinal sin)
There is not one test, KAT, or proptest in the repo. The TCP server's credibility came from the benchmark harness; a crypto primitive's credibility comes from test vectors and adversarial tests. Without them, every correctness claim is a vibe.

### 1.7 What is actually correct (credit where due — honesty cuts both ways)
- The **Feldman VSS structure** is right: round1 publishes `C_k = a_k·G`; round2 verifies `share·G == Σ_k C_k · i^k`.
- **curve25519-dalek / Ed25519** is the correct curve for Solana-compatible threshold Schnorr, and dalek 4 gives constant-time scalar/point arithmetic by default.
- The **Lagrange-at-zero** interpolation is correct.
- The instinct to verify `z·G == R + c·X` before returning is the right reflex.

**Reality check:** the owner believes there is a working t-of-n threshold MPC system. There is a coordinator-trusted, concurrency-forgeable, plaintext-share, untested signing flow that has only ever been exercised at the **degenerate t = n = 2** case (where Lagrange is trivial and the t < n paths never run). The variable named `degree` in `round1` actually holds the *coefficient count*, and its inline comment contradicts the code — the math is correct for t-of-n but unverified anywhere but the 2-of-2 corner.

---

## 2. Target architecture

Collapse the distributed shell into **one sans-IO library crate**. The protocol is pure functions and explicit message types over participant state machines — no network, no DB, no Solana SDK in the trust-critical path. This is the same move that froze the TCP `core` and drove all 11 models unchanged.

**Recommended rename:** the repo reads as an app. Reposition as **`frost-ed25519-kit`** (GitHub rename preserves the redirect). "Solana-compatible" becomes a one-line property — Ed25519 → Solana addresses — *proven by an offline-verify example, not an SDK integration.*

```
frost-ed25519-kit/
  Cargo.toml                    # workspace; #![forbid(unsafe_code)] crate-wide
  frost-core/                   # THE primitive — sans-IO, no I/O, no DB, no SDK (FROZEN once green)
    src/
      group.rs                  # validated CT (de)serialization: canonical scalars, prime-order
                                #   point checks (cofactor), length checks — reject, never coerce
      secret.rs                 # Zeroizing wrappers for shares/nonces/coeffs; no Debug leak; single-use nonces by type
      vss.rs                    # Feldman commitments + verification (pure fns) — port the correct existing logic
      keygen.rs                 # trusted-dealer + Pedersen DKG state machine (no secret ever leaves the holder)
      sign.rs                   # FROST round1 (D_i,E_i) / round2 (binding factor, group commitment, z_i) / aggregate
      verify.rs                 # standard RFC 8032 Ed25519 verification (cofactored)
      message.rs                # explicit wire message types (serde) — transport-agnostic, never sent secrets
      error.rs                  # fallible APIs; zero panics on peer-controlled input
    tests/
      rfc9591_kat.rs            # known-answer vectors — byte-for-byte
      differential.rs           # proptest vs ZcashFoundation `frost-ed25519` as oracle
      reconstruction.rs         # any t reconstruct; any t-1 reveal nothing
      adversarial.rs            # malformed / non-canonical / low-order / wrong-index / replayed nonce
      ros_resistance.rs         # the attack succeeds vs naive scheme, fails vs FROST
  examples/
    in_process_2of3.rs          # n participants in ONE process over channels — no HTTP, no DB
    solana_compat.rs            # produce a sig; verify offline against ed25519-dalek; print the Solana address. NO RPC, NO broadcast.
  fuzz/                         # cargo-fuzz targets on the deserializers
  docs/
    ARCHITECTURE.md
    THREAT-MODEL.md
    specs/                      # this brief + per-phase specs
  README.md                     # systems-crypto primitive, pinned on profile
```

**Drop entirely:** `orchestrator/`, `node/`, `store/`, `nodeDb/`; `poem`, `tokio`, `reqwest`, `diesel`, Postgres, the migrations; `solana-sdk`, `solana-client`, `spl-token`, `spl-associated-token-account`, `bincode`, `base64`, `bs58` (the broadcast path); the committed `.env`; the absolute `diesel.toml` path.

**The protocol is the product. The transport is an instance.** Keygen, signing, and verification live once in `frost-core` as pure functions feeding participant state machines. An `examples/` harness simulates n parties in-process over channels. If networking is ever wanted, it wraps the core unchanged — exactly as the TCP models wrapped the frozen `core`.

---

## 3. The protocol — what to build

### 3.1 FROST-Ed25519 signing (the headline — replaces §1.2)
Implement FROST (Komlo–Goldberg; standardized in **RFC 9591**, Aug 2024) on `curve25519-dalek`:
- **Round 1 (commit):** each signer samples a *pair* of nonces `(d_i, e_i)`, publishes commitments `(D_i = d_i·G, E_i = e_i·G)`. Nonces are single-use, unpredictable, zeroized after the round.
- **Round 2 (sign):** compute the per-signer **binding factor** `ρ_i = H("FROST-ED25519…rho", i, msg, B)` over the full commitment list `B`; the group commitment `R = Σ (D_i + ρ_i·E_i)`; challenge `c = H(R ‖ X ‖ msg)`; partial `z_i = d_i + ρ_i·e_i + λ_i·c·s_i`.
- **Aggregate:** `z = Σ z_i`; signature `(R, z)`; verify `[8]z·G == [8]R + [8]c·X` (cofactored, RFC 8032).
- **The binding factor is the whole point.** It binds every nonce to the message and the exact signer set, so an adversary cannot linearly combine across concurrent sessions — the ROS defense the naive scheme lacks. State this explicitly in code comments and ARCHITECTURE.md.

**Hand-roll it.** Using `frost-ed25519` wholesale is the tokio of this repo — it defeats the point. Hand-rolling on raw dalek is the signal: it shows you understand the construction, not just an API. **But hand-rolled crypto that is subtly wrong is worse than none** — a reviewer who finds the bug is disqualifying. The discipline that makes hand-rolling safe is the same measure-never-guess move as cross-checking the loadgen with wrk2: **the implementation MUST pass the RFC 9591 KATs byte-for-byte and MUST differentially match `frost-ed25519` on randomized inputs. If it cannot, that is a STOP, not a "good enough."** Test vectors, not vibes.

### 3.2 Key generation
Keep verifiable DKG — "no trusted dealer" is real signal and the Feldman bones already exist — but fix it to a proper **Pedersen DKG**: commit-to-commitments first, then reveal, with Feldman verification and a complaint round, so a malicious dealer cannot bias the key (the Gennaro et al. result that plain Feldman DKG is biasable). **Fallback if DKG comprehension stalls:** ship trusted-dealer keygen *clearly documented as the trust assumption* and move Pedersen DKG to a later phase. Do not ship a subtly-broken DKG to look more decentralized — honesty-as-signal. The opinionated call is: do the Pedersen DKG, in its own phase, after signing is green.

---

## 4. The common bar — the high-signal primitives a Principal Security/Systems Engineer evaluates

Every one of these is checked on sight. The repo is not done until all hold.

1. **A standardized protocol, not a homemade scheme.** FROST/RFC 9591, named and cited. No bespoke threshold construction.
2. **Validation against published test vectors** (RFC 9591 KATs) **plus differential testing** against an independent implementation. This is the falsifiable core.
3. **Constant-time secret-dependent operations.** dalek scalar/point ops are CT; no secret-dependent branching in your code; no early-return that leaks a secret bit via timing.
4. **Zeroization of all secret material.** `Zeroizing`/`zeroize` on shares, nonces, coefficients; `Drop` discipline; secrets never derive `Debug`, never reach a log line.
5. **Validated deserialization.** Canonical-scalar enforcement; prime-order-subgroup (cofactor) checks on every peer point; length checks. Reject, never silently coerce. Adversarial tests prove rejection.
6. **Nonce discipline.** Single-use (enforced by consuming the nonce by value at the type level), unpredictable, bound to message + signer set via the binding factor — the exact thing the old code got catastrophically wrong.
7. **Rogue-key resistance** in DKG/aggregation; documented.
8. **An honest, explicit threat model.** Trust boundaries; what a `k < t` adversary learns (nothing); what the coordinator can and cannot do; network assumptions; the ROS/concurrent-signing defense; small-subgroup; out-of-scope.
9. **Minimal, audited dependency surface.** `#![forbid(unsafe_code)]` crate-wide; `cargo audit` + `cargo deny` clean; `clippy -D warnings`.
10. **Sans-IO design.** The trust-critical path has no network or DB; it is unit-testable in-process.
11. **No panics on peer-controlled input.** Every parse/verify path returns `Result`.

---

## 5. The validation harness (the crypto analogue of the benchmark)

A model server earns trust with numbers; a crypto primitive earns it with vectors and adversaries. Build the harness *early* so every piece is validated the moment it compiles.

- **Known-answer tests (`tests/rfc9591_kat.rs`).** The RFC 9591 FROST(Ed25519, SHA-512) vectors: fixed inputs → group commitment, binding factors, partial signatures, and final signature match **byte-for-byte**. A failure here is a STOP.
- **Differential proptest (`tests/differential.rs`).** Against ZcashFoundation `frost-ed25519` as the oracle, over ≥10,000 randomized cases sweeping `(t, n)` with `t ≤ n`: identical group keys, identical aggregate signatures, identical accept/reject.
- **Reconstruction property (`tests/reconstruction.rs`).** Any `t` shares reconstruct the group key; any `t-1` shares interpolate to a key uncorrelated with the true one (the information-theoretic statement, exercised).
- **Adversarial suite (`tests/adversarial.rs`).** Malformed encodings, non-canonical scalars, low-order points, wrong-index shares, replayed/reused nonces — each must be *rejected*, not coerced or panicked.
- **ROS resistance (`tests/ros_resistance.rs`).** Implement the concurrent-session forgery and show it **succeeds against the archived naive scheme and fails against FROST.** This single test is the most senior artifact in the repo — keep a frozen copy of the old construction in a `legacy/` module purely as the attack target.
- **Fuzzing (`fuzz/`).** `cargo-fuzz` targets on every deserializer. No panics, no crashes on arbitrary bytes.
- **Reproducible.** One command runs the full suite; CI green on every push; document the toolchain.

---

## 6. Hard Definition of Done

World-class-artifact-grade only when **all** of these are true:

1. The primitive is a single **sans-IO library**. No network, DB, or Solana SDK in the cryptographic path. `#![forbid(unsafe_code)]` crate-wide. `orchestrator`/`node`/`store`/`nodeDb` deleted.
2. FROST-Ed25519 signing **passes the RFC 9591 KATs byte-for-byte** and **differentially matches `frost-ed25519`** on ≥10,000 randomized proptest cases across varied `(t, n)`.
3. Reconstruction property proven in tests: any `t` reconstruct; any `t-1` reveal nothing.
4. **Concurrent-session forgery resistance demonstrated:** the ROS/Drijvers attack succeeds against the archived naive scheme and fails against FROST, in a committed test.
5. All secret material wrapped in `Zeroizing`/zeroized on drop; secrets never derive `Debug` or reach a log; nonces single-use enforced by type. A leak-audit test or `cargo` lint confirms it.
6. Validated deserialization: non-canonical scalars and non-prime-order points **rejected**, proven by adversarial tests. Zero `unwrap`/`expect`/`panic!` on peer-controlled input — every such path returns `Result`.
7. `docs/THREAT-MODEL.md` complete per §4.8: trust boundaries, adversary model, the explicit ROS defense, rogue-key, small-subgroup, coordinator trust, out-of-scope.
8. `cargo audit` + `cargo deny` clean; dependency allowlist respected; `clippy -D warnings`; CI green.
9. `docs/ARCHITECTURE.md`: the sans-IO boundary, message types, and **rejected alternatives** — naive threshold Schnorr and *precisely why* it is broken; trusted-dealer vs Pedersen DKG; hand-roll-plus-differential-test vs `frost-ed25519` wholesale.
10. `README.md` positions it as a systems-crypto primitive, 60-second grasp above the fold, no frontend, no app glue; the `solana_compat` example proves Ed25519/Solana-address compatibility with an **offline** verification — no RPC, no broadcast. The committed `.env` is purged from history; `diesel.toml`'s absolute path is gone with the crate.
11. **Self-audit passed (the comprehension gate):** the owner can re-derive the FROST binding factor from memory and explain why it defeats ROS where `R = ΣR_i` does not. If you cannot explain it, you do not own it, and it cannot support the flagship.

---

## 7. Non-negotiable engineering rules (the discipline that signals "elite")

1. **Test vectors, never vibes.** Every correctness claim traces to a KAT or a differential proptest. Crypto intuition is wrong by default and dangerous when wrong.
2. **No secret on a path that isn't the work.** No secret in a log, a `Debug`, a serialized message, a DB, or an un-zeroized buffer. The secret leaves a holder only as a partial signature — never as a share.
3. **Reject, never coerce.** Non-canonical, out-of-subgroup, wrong-length: a `Result::Err`, not a silent reduction.
4. **One bad peer must never abort the protocol.** Every parse/verify is fallible. Malformed input is a rejected message, not a panic.
5. **Standardized over clever.** Implement the published, peer-reviewed, RFC'd construction. Bespoke threshold crypto is how you get found out.
6. **Hand-roll the mechanism, oracle the result.** Hand-rolling on raw dalek is the signal; the KAT + differential oracle is what makes it safe. Both, always.
7. **Sans-IO.** The protocol is pure functions and state machines. Transport is a wrapper, never in the trust path.
8. **Honesty is the signal.** Document the trust assumption (trusted dealer if DKG is deferred), the attack the old code fell to, and anything unverified beyond the cases tested. An honest, scoped primitive beats an over-claimed one.
9. **Minimal surface.** Fewer dependencies, all audited. `#![forbid(unsafe_code)]`. Every crate justifiable.
10. **Scope discipline.** One session, one deliverable, ends `cargo build`/`clippy`/`test` green + commit + STOP. Future phases are off-limits until reached.

Use the vocabulary — *binding factor, ROS, cofactor / small-subgroup, canonical encoding, constant-time, sans-IO, rogue-key, verifiable secret sharing* — **only after the technique is actually applied.** Decorative crypto jargon is detected instantly and is worse than plain language. Earn the term, then use it.

---

## 8. Build order (phases sized for autonomous Claude Code sessions)

**Phase 0 — Foundation: sans-IO core + validated group layer (FROZEN once green).**
Stand up `frost-core`: `group.rs` (canonical-scalar + prime-order-point validated (de)serialization), `secret.rs` (`Zeroizing` secret types, single-use nonce types), `error.rs`, `message.rs`. Port the *correct* Feldman VSS logic into `vss.rs` as pure functions. Trusted-dealer `keygen.rs`. Green gate: a `reconstruction.rs` test proving 2-of-3 and 3-of-5 trusted-dealer sharing reconstructs the group key (reconstruction in tests only — never in protocol). Delete `orchestrator`/`node`/`store`/`nodeDb` and purge the committed `.env` from history. **`frost-core` is frozen after this phase** — if signing later seems to need a core change, the signing design is wrong; STOP and ask.

**Phase 1 — FROST-Ed25519 signing + the KAT/differential harness (the headline).**
Implement `sign.rs` (two-nonce round 1; binding factor, group commitment, partial in round 2; aggregate) and `verify.rs` (cofactored RFC 8032). Stand up `tests/rfc9591_kat.rs` and `tests/differential.rs` the moment the first value computes. Enforce single-use, zeroized nonces. Green gate: KATs byte-for-byte + differential proptest ≥10k cases. Archive the old naive scheme into `legacy/` for Phase 3's attack target.

**Phase 2 — Verifiable DKG (Pedersen) or documented trusted-dealer.**
Harden Feldman into a Pedersen DKG: commit-then-reveal, Feldman verification, complaint round, rogue-key resistance. Proptest: any `t` reconstruct, any `t-1` cannot, malicious dealer detected. If comprehension is at risk, ship trusted-dealer + the threat-model trust note and defer DKG — honestly. (Opinionated default: do the DKG.)

**Phase 3 — Adversarial hardening + threat model + secret-hygiene audit.**
`tests/adversarial.rs` (malformed / non-canonical / low-order / wrong-index / replay) and `tests/ros_resistance.rs` (forgery succeeds vs `legacy/`, fails vs FROST). `fuzz/` targets on the deserializers. `cargo audit` + `cargo deny`. Write `docs/THREAT-MODEL.md`. Zeroization leak-audit.

**Phase 4 — Artifacts + distribution.**
`README.md` (systems-crypto primitive, 60-sec grasp, no app glue), `docs/ARCHITECTURE.md` (sans-IO boundary + rejected alternatives table), the `examples/in_process_2of3.rs` and `examples/solana_compat.rs` (offline verify, no broadcast), and the distribution thread — built only from committed test results, inventing nothing. Verify DoD §6 item by item.

---

## 9. Out of scope — do NOT do these

- No HTTP servers, no orchestrator, no nodes, no message bus. The protocol is a library; `examples/` simulates parties in-process over channels.
- No database, no Diesel, no persistence in the crypto path.
- **No Solana SDK, no RPC, no devnet, no SPL-token, no broadcast.** Solana compatibility is one offline-verified example proving Ed25519 → Solana-address, nothing more.
- No frontend, no styled HTML, no CLI beyond a test/example runner.
- No bespoke threshold construction. FROST/RFC 9591 only.
- **No use of `frost-ed25519` in the shipped crate** — it is the differential *oracle in tests*, never the implementation.
- Do not exceed the build order. Resist adding curves, transports, or features not in §2–§3.
- Do not over-claim. If only trusted-dealer keygen ships, the README and threat model say so plainly.

---

## 10. First message for the executing chat

Paste this brief, then start with:

> "Execute Phase 0. Create the `frost-ed25519-kit` workspace per §2 with `#![forbid(unsafe_code)]`: stand up `frost-core` with `group.rs` (canonical-scalar + prime-order-point validated (de)serialization, reject-never-coerce), `secret.rs` (`Zeroizing` secret types, single-use nonce types, no `Debug` on secrets), `error.rs`, `message.rs`, and port the correct Feldman VSS logic into `vss.rs` as pure functions with trusted-dealer `keygen.rs`. Delete `orchestrator`/`node`/`store`/`nodeDb` and purge the committed `nodeDb/.env` from history. Get a `reconstruction.rs` test green proving 2-of-3 and 3-of-5 trusted-dealer sharing reconstructs the group key. Show me the workspace tree and the `frost-core` public API before writing any signing code. `frost-core` freezes after this phase."

---

## Appendix A — `CLAUDE.md` for this repo

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md  — strategy, audit, target architecture, common bar, DoD
- docs/specs/phase0-spec.md    — frost-core foundation (FROZEN after Phase 0)
- docs/specs/phase1-spec.md    — FROST-Ed25519 signing + KAT/differential harness
- docs/specs/phase2-spec.md    — Pedersen DKG (or documented trusted-dealer)
- docs/specs/phase3-spec.md    — adversarial suite, ROS test, fuzz, threat model
- docs/specs/phase4-spec.md    — README/ARCHITECTURE/examples, distribution

## Hard rules
1. frost-core is sans-IO and FROZEN after Phase 0. No network/DB/Solana SDK in the
   crypto path. #![forbid(unsafe_code)] crate-wide.
2. Hand-roll FROST on raw curve25519-dalek. `frost-ed25519` is the test oracle ONLY,
   never the implementation. RFC 9591 KATs must pass byte-for-byte or STOP.
3. No secret on any path that isn't the work: no Debug, no logs, no serialization,
   no plaintext-at-rest. Zeroize all secret material; nonces single-use by type.
4. Reject, never coerce: non-canonical scalars, out-of-subgroup points, wrong lengths
   return Result::Err. Zero panics on peer-controlled input.
5. Honesty: document the trust assumption, the attack the legacy scheme falls to,
   and anything unverified beyond the tested cases. Build writeups only from committed
   test results — invent nothing. No marketing words, no emoji, no exclamation.

## Scope discipline
Work ONLY on the given session. End with cargo build+clippy+test (and audit/deny where
applicable), list changes, STOP.
```

## Appendix B — Claude Code execution plan

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 0.1 | Demolition + scaffold | delete shell crates, purge `.env` from history, workspace + `frost-core` skeleton, `#![forbid(unsafe_code)]` | `cargo build` clean, tree shown |
| 0.2 | Group + secret layer | `group.rs` validated CT (de)ser, `secret.rs` Zeroizing/single-use types, `error.rs`, `message.rs` | adversarial parse stubs reject; no `Debug` on secrets |
| 0.3 | VSS + trusted-dealer keygen | port Feldman `vss.rs`, `keygen.rs`, `reconstruction.rs` | 2-of-3 + 3-of-5 reconstruct green; **frost-core FROZEN** |
| 1.1 | FROST round 1 + 2 + aggregate | `sign.rs` (two-nonce, binding factor, group commitment, partial, aggregate) | computes a signature for 2-of-3 |
| 1.2 | Verify + KAT harness | `verify.rs` cofactored; `tests/rfc9591_kat.rs` | RFC 9591 vectors match byte-for-byte |
| 1.3 | Differential harness | `tests/differential.rs` vs `frost-ed25519` | ≥10k randomized `(t,n)` cases identical; archive `legacy/` naive scheme |
| 2.1 | Pedersen DKG | `keygen.rs` commit-then-reveal + complaint round + rogue-key resistance | proptest: t reconstruct, t-1 cannot, bad dealer detected (or trusted-dealer documented) |
| 3.1 | Adversarial + ROS | `tests/adversarial.rs`, `tests/ros_resistance.rs` | rejections proven; forgery succeeds vs legacy, fails vs FROST |
| 3.2 | Fuzz + audit + threat model | `fuzz/` deserializer targets, `cargo audit`/`deny`, `docs/THREAT-MODEL.md` | no fuzz crashes; audits clean; threat model complete |
| 4.1 | README + ARCHITECTURE + examples | README, ARCHITECTURE (rejected-alternatives table), `in_process_2of3` + `solana_compat` (offline) | 60-sec grasp; examples run; DoD §6 verified item by item |

Session 1.1 is the heavy crypto build — split at the round-1 / round-2 boundary if context grows. Test-heavy sessions (1.2, 1.3, 3.x) carry large context; keep them separate so each gets a clean window. Final phase — no Phase 5.
