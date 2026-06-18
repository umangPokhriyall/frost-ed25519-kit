# frost-ed25519-kit — Phase 1 Specification: FROST-Ed25519 Signing, Identifiable Abort, and the Validation Harness

**Companion to:** `docs/specs/kickoff-brief.md`, `docs/specs/kickoff-amendment-1.md`, `docs/specs/phase0-spec.md`. Read all three first.
**This is the complete, authoritative Phase 1 spec.** It covers FROST-Ed25519 two-round signing (hand-rolled on the frozen `frost-core`), hedged nonce generation, per-partial verification with identifiable abort, RFC 8032 aggregate verification, and the validation harness: intermediate-first RFC 9591 KATs and a differential proptest against `frost-ed25519`.
**Audience:** Claude Code. Authoritative. This is the headline cryptographic phase.

---

## 1. Phase 1 in one paragraph

Implement FROST(Ed25519, SHA-512) per RFC 9591 as pure functions and a participant state machine over the **frozen** `frost-core`. Round 1 produces hedged single-use nonce pairs and their commitments; round 2 computes the per-signer binding factor, the group commitment, and a partial signature; the aggregator **verifies every partial against its public verifying share before summing** and names the culprit on failure; the result is a standard Ed25519 signature that verifies under RFC 8032. The implementation is hand-rolled on `curve25519-dalek` — `frost-ed25519` is the differential oracle in tests, never a dependency of the shipped crate. Correctness is proven the only way crypto correctness can be: the RFC 9591 known-answer vectors, asserted **intermediates-first** (binding factors → group commitment → partials → final signature), and a differential proptest against `frost-ed25519` over ≥10,000 randomized `(t, n)` cases. The legacy naive scheme is archived in `legacy/` as the Phase 3 attack target.

### 1.1 Frozen / reused
- **`group.rs`, `secret.rs`, `message.rs`, `vss.rs` are frozen (Phase 0).** Signing uses them unchanged. If signing appears to need a change to any of them, the signing design is wrong — STOP and ask.
- **`keygen.rs` is reused unchanged.** Phase 1 consumes `KeyPackage` and `PublicKeyPackage` (with `verifying_shares`) exactly as Phase 0 emits them.
- **`frost-core` gains exactly three files:** `nonces.rs` (or fold into `secret.rs` body — but the type is frozen), `sign.rs`, `verify.rs`. The single-use `SigningNonces` *type* is frozen; Phase 1 fills its hedged *constructor* and its consuming `into_partial`.

---

## 2. Workspace additions & dependencies

```
frost-core/src/sign.rs                 # NEW — round 1, round 2, aggregate (with identifiable abort)
frost-core/src/verify.rs               # NEW — RFC 8032 aggregate verify + verifying-share check
frost-core/tests/rfc9591_kat.rs        # NEW — intermediates-first KAT (amendment §4)
frost-core/tests/differential.rs       # NEW — proptest vs frost-ed25519
frost-core/tests/identifiable_abort.rs # NEW — amendment §2
frost-core/tests/vectors/              # NEW — committed RFC 9591 vector JSON (vendored, sourced)
legacy/                                # NEW crate — archived naive scheme (Phase 3 target; built, not wired)
```

Dependency additions:
```toml
# frost-core dev-dependencies ONLY (never in the shipped crate graph):
frost-ed25519 = "2"            # differential oracle — tests only
proptest      = "1"
serde_json    = "1"            # decode the committed RFC 9591 vectors
```
The shipped `frost-core` library graph stays exactly as Phase 0 left it (`curve25519-dalek`, `zeroize`, `rand_core`, `subtle`, `thiserror`). Verify with `cargo tree -e normal` that `frost-ed25519` does **not** appear outside dev-deps. `legacy/` depends only on `curve25519-dalek` + `rand` and is excluded from the public API surface.

---

## 3. The ciphersuite constants — verify, never assume

Hand-rolling FROST means the hash-input encodings are the entire risk surface. **Verify each of the following against RFC 9591 §6.1 (FROST(Ed25519, SHA-512)) and the `frost-ed25519` source before writing the body; the intermediate KATs (§7) are the guard that catches a deviation.**

- `contextString = "FROST-ED25519-SHA512-v1"` (confirm exact bytes).
- **H1 — binding factor / rho:** `hash_to_scalar(contextString ‖ "rho" ‖ input)` → reduce mod L. Confirm the label and that reduction is mod-order-wide over the 64-byte SHA-512 output.
- **H2 — challenge:** SHA-512 over `(R_enc ‖ group_public_enc ‖ msg)` reduced mod L. **Ed25519-specific: no contextString** here, for RFC 8032 verifier compatibility. Confirm this exception.
- **H3 — nonce derivation:** `hash_to_scalar(contextString ‖ "nonce" ‖ input)` — used by the hedged constructor (§5).
- **H4 — message hash:** SHA-512 over `(contextString ‖ "msg" ‖ msg)`.
- **H5 — commitment-list hash:** SHA-512 over `(contextString ‖ "com" ‖ encoded_commitment_list)`.
- **Commitment-list encoding:** the list of `(identifier, D_i, E_i)` **sorted by identifier**, each encoded as `id_enc(32) ‖ D_enc(32) ‖ E_enc(32)`. The sort and the length-exact encoding are where one-byte deviations hide.

Put these in a `ciphersuite` module with the labels as named constants, each with a `// RFC 9591 §x.y` provenance comment.

---

## 4. `sign.rs` — round 1, round 2, aggregate

### 4.1 Round 1 — commit (hedged, single-use) — amendment §3
```rust
/// Generate a single-use nonce pair, hedged against RNG failure (amendment §3):
///   d = H3(random_bytes(32) ‖ encode(signing_share))
///   e = H3(random_bytes(32) ‖ encode(signing_share))   // independent random
/// Returns the secret SigningNonces (kept by the signer) and the public commitments (D_i, E_i).
pub fn commit(signing_share: &SigningShare, rng: &mut impl rand_core::CryptoRng)
    -> (SigningNonces, SigningCommitments);

pub struct SigningCommitments { pub id: Identifier, pub hiding: GElement /*D_i*/, pub binding: GElement /*E_i*/ }
```
`SigningNonces` is the frozen single-use type from Phase 0: it has no `Clone`/`Copy`, is `ZeroizeOnDrop`, and is **consumed by value** in round 2. The hedge means a fully predictable RNG still cannot cause nonce reuse, because the share entropy is mixed in. One sentence in `THREAT-MODEL.md` (Phase 3) records this; the PS3 nonce-reuse failure is the cautionary reference.

### 4.2 Round 2 — sign
```rust
/// commitments: the full set (id, D_i, E_i) for the chosen signer set, used to derive binding factors.
pub fn sign(
    signing_share: &SigningShare,
    nonces: SigningNonces,                    // consumed — single use enforced by the type
    my_id: Identifier,
    commitments: &[SigningCommitments],       // the signer set
    public: &PublicKeyPackage,
    msg: &[u8],
) -> Result<SignatureShare, Error>;

pub struct SignatureShare { pub id: Identifier, pub z: GScalar }
```
Internally:
1. `validate_identifier_set` over the signer set; require `|set| >= threshold`.
2. `msg_hash = H4(msg)`; `com_hash = H5(encode_commitment_list(commitments))`.
3. For each signer `j`: `ρ_j = H1(msg_hash ‖ com_hash ‖ id_enc(j))`.
4. Group commitment `R = Σ_j (D_j + ρ_j · E_j)`.
5. Challenge `c = H2(R_enc ‖ group_public_enc ‖ msg)`.
6. Lagrange `λ_i` for `my_id` over the signer set (use the frozen helper).
7. `z_i = d_i + (ρ_i · e_i) + (λ_i · c · s_i)` — `nonces` consumed here, then dropped (zeroized).

### 4.3 Aggregate — with identifiable abort (amendment §2)
```rust
pub fn aggregate(
    shares: &[SignatureShare],
    commitments: &[SigningCommitments],
    public: &PublicKeyPackage,
    msg: &[u8],
) -> Result<Signature, Error>;

pub struct Signature { pub r: GElement, pub z: GScalar } // serializes to 64 bytes: R_enc ‖ z_enc
```
Recompute `R`, the `ρ_j`, `c`, and each `λ_j`. **Before summing, verify every partial:**
```
z_j·G  ==  (D_j + ρ_j·E_j)  +  (λ_j · c · X_j)
```
where `X_j = public.verifying_shares[id_j]` (the Phase 0 verifying share). On the first failure, return `Err(Error::Culprit(id_j))`. Only when all pass: `z = Σ z_j`, `R = Σ (D_j + ρ_j E_j)`, return `Signature { r: R, z }`. Finally, assert the aggregate verifies (§5) before returning; an aggregate failure after all partials verified is an internal bug — `debug_assert!` and return `InvalidSignature`.

---

## 5. `verify.rs` — RFC 8032 verification

```rust
/// Standard Ed25519 verification of (R, z) under the group public key.
/// Uses the RFC 8032 verification equation so the output is a valid, interoperable Ed25519 signature.
pub fn verify(public: &GElement, msg: &[u8], sig: &Signature) -> Result<(), Error>;

/// The per-partial check used by aggregate(); exposed for tests.
pub fn verify_share(
    share: &SignatureShare, commitments: &[SigningCommitments],
    public: &PublicKeyPackage, msg: &[u8],
) -> Result<(), Error>;
```
`verify` computes `c = H2(R_enc ‖ A_enc ‖ msg)` and checks the RFC 8032 equation (`[8]z·G == [8]R + [8]c·A` cofactored, matching the standard verifier). The point of being RFC 8032-shaped: the same signature verifies under any off-the-shelf Ed25519 verifier — proven offline in the Phase 4 `solana_compat` example, never broadcast.

---

## 6. `message.rs` usage

`SigningCommitments`, `SignatureShare`, and `Signature` are transport-agnostic value types. They MAY derive `Serialize`/`Deserialize` (they carry no secret). `SigningNonces` and `SigningShare` MUST NOT — enforced since Phase 0. No transport is built this phase; the Phase 4 `examples/in_process_2of3.rs` moves these over channels.

---

## 7. The validation harness — intermediates first (amendment §4)

### 7.1 `tests/rfc9591_kat.rs` — ordering is mandatory
Vendor the RFC 9591 FROST(Ed25519, SHA-512) test vectors into `tests/vectors/` as committed JSON, with a header comment citing the RFC section and the retrieval date. Assert in this order, each gating the next so a failure localizes:
1. **Binding factors `ρ_i`** match the vector for every signer.
2. **Group commitment `R`** matches.
3. **Per-signer partial signatures `z_i`** match.
4. **Final signature `(R, z)`** matches byte-for-byte, AND `verify(...)` accepts it.

A deviation in the `ρ` preimage encoding (a length prefix, the sort order, a domain label) surfaces at step 1 with exact localization instead of an unattributable failure at step 4. If step 1 fails, fix the H1/commitment-list encoding against §3 before proceeding — do not chase the final byte.

### 7.2 `tests/differential.rs` — oracle vs hand-roll
Proptest over ≥10,000 cases, randomizing `(t, n)` with `2 ≤ t ≤ n ≤ 8`, the signer subset, the message, and the seed. For each case, run keygen → commit → sign → aggregate in **both** `frost-core` and `frost-ed25519` from the same seed, and assert:
- identical `group_public`,
- identical aggregate `Signature` bytes,
- identical accept/reject decisions,
- `frost-core`'s signature verifies under `frost-ed25519`'s verifier and vice versa.
Use `frost-ed25519`'s trusted-dealer/keygen as the oracle path; align identifiers and the signer set. Any divergence is a STOP.

### 7.3 `tests/identifiable_abort.rs` — amendment §2
- A 2-of-3 (and a 3-of-5) signing run where one signer submits a garbage `z_j`: `aggregate` returns `Err(Culprit(that_id))`, and an otherwise-identical honest run succeeds.
- A signer submits a partial computed with the wrong `λ` (wrong signer set): caught as `Culprit`.
- `verify_share` accepts every honest partial.

---

## 8. `legacy/` — archive the attack target (build only; Phase 3 wires it)

Reimplement the legacy scheme's *math* (not the HTTP code) as the single-key Schnorr oracle specified in amendment §1: `open_session() → R_i`, `sign(session, msg) → z_i = r_i + H(R_i ‖ X ‖ msg)·s`, unlimited concurrency, no binding factor. Build it, give it a smoke test (one session signs and verifies), and STOP — the ROS solver and `tests/ros_resistance.rs` are Phase 3. The reduction comment (threshold aggregate collapses to single-key) goes in the oracle's doc-comment now.

---

## 9. Phase 1 Definition of Done

1. `frost-core` Phase 0 modules byte-for-byte unchanged (`group`/`secret`/`message`/`vss` frozen; `keygen` unchanged).
2. `sign.rs` implements hedged `commit`, `sign`, and `aggregate` with identifiable abort; `SigningNonces` single-use enforced by type (consumed by value).
3. **RFC 9591 KATs pass intermediates-first** (§7.1): `ρ_i`, then `R`, then `z_i`, then the final signature byte-for-byte.
4. **Differential proptest** (§7.2) green over ≥10,000 randomized `(t, n)` cases against `frost-ed25519`; cross-verification both directions.
5. **Identifiable abort** (§7.3): a bad partial yields `Culprit(id)`; honest set unaffected; proven for 2-of-3 and 3-of-5.
6. **Hedged nonces** (§4.1): nonce derivation mixes share entropy; a deterministic-RNG test shows two `commit` calls with the *same* RNG state still yield different nonces because the share differs / the construction does not reuse.
7. `verify.rs` accepts FROST-produced signatures under the RFC 8032 equation; a tampered signature is rejected.
8. `frost-ed25519` appears only in dev-dependencies (`cargo tree -e normal` proves it); shipped graph unchanged from Phase 0; `#![forbid(unsafe_code)]` intact.
9. `legacy/` oracle built with the reduction doc-comment and a smoke test; not wired into `frost-core`.
10. `cargo build`, `cargo clippy -D warnings`, `cargo test` clean.
11. **Self-audit (comprehension gate):** the owner can re-derive `z_i = d_i + ρ_i e_i + λ_i c s_i` and state why the binding factor makes the ROS linear system non-existent — from memory.

No DKG (Phase 2), no ROS solver (Phase 3), no README/threat-model prose (Phases 3–4) this phase.

---

## Appendix A — `CLAUDE.md` update for Phase 1

```markdown
## Hard rules (Phase 1 additions)
6. Hand-roll FROST on curve25519-dalek. `frost-ed25519` is a DEV-DEPENDENCY ORACLE ONLY;
   it must never enter the shipped graph (verify with cargo tree -e normal).
7. RFC 9591 KATs assert intermediates FIRST: rho_i -> R -> z_i -> final signature.
   A failure before the final byte means fix the encoding, not the final check.
8. Every partial is verified against X_i before aggregation; a bad partial returns
   Culprit(id). Nonces are hedged H3(random ‖ share) and single-use by type.
9. legacy/ is the Phase 3 attack target: single-key Schnorr oracle, no binding factor.
   Build + smoke-test only this phase; do not wire it into frost-core.
```

## Appendix B — Claude Code execution plan (Phase 1)

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 1.1 | Ciphersuite + round 1/2 | `ciphersuite` constants (§3), `sign.rs` `commit` (hedged) + `sign` (§4.1–4.2) | computes `R`, `c`, a partial for 2-of-3; constants carry RFC provenance |
| 1.2 | Aggregate + verify | `sign.rs` `aggregate` with identifiable abort (§4.3), `verify.rs` (§5) | a 2-of-3 signature verifies under RFC 8032; bad partial → `Culprit` |
| 1.3 | Intermediate KATs | `tests/vectors/` + `tests/rfc9591_kat.rs` intermediates-first (§7.1) | `ρ_i` → `R` → `z_i` → final all match the vectors |
| 1.4 | Differential + abort tests | `tests/differential.rs` (§7.2), `tests/identifiable_abort.rs` (§7.3) | ≥10k cases match `frost-ed25519`; abort names the culprit |
| 1.5 | Legacy archive | `legacy/` single-key oracle + reduction doc-comment + smoke test (§8) | builds; one session signs+verifies; not wired in |

**Session 1.1 prompt**
> Read `phase1-spec.md` §1–§4.2 and `kickoff-amendment-1.md` §3–§4. Execute **Session 1.1 only**: add a `ciphersuite` module with the H1–H5 labels, contextString, and commitment-list encoding as named constants, each with an RFC 9591 provenance comment — verify them against RFC 9591 §6.1 and the `frost-ed25519` source before writing the body. Implement `sign.rs` `commit` (hedged `H3(random ‖ share)`, returning the frozen single-use `SigningNonces` + public `SigningCommitments`) and `sign` (binding factors, group commitment, challenge, Lagrange, partial). Do not touch frozen modules. Add `frost-ed25519`, `proptest`, `serde_json` to dev-deps only. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 1.2 prompt**
> Read `phase1-spec.md` §4.3–§6. Execute **Session 1.2 only**: implement `aggregate` with per-partial verification against `X_j` and `Err(Culprit(id))` on failure (amendment §2), and `verify.rs` (RFC 8032 aggregate verify + `verify_share`). A 2-of-3 end-to-end signature must verify. Do not touch frozen modules. Commit, run checks, list changes, STOP.

**Session 1.3 prompt**
> Read `phase1-spec.md` §7.1 and `kickoff-amendment-1.md` §4. Execute **Session 1.3 only**: vendor the RFC 9591 FROST(Ed25519,SHA-512) vectors into `tests/vectors/` (cite section + retrieval date) and write `tests/rfc9591_kat.rs` asserting intermediates-first: binding factors → group commitment → per-signer partials → final signature byte-for-byte. If an intermediate fails, fix the §3 encoding, not the final check. Commit, run checks, report which intermediates passed, STOP.

**Session 1.4 prompt**
> Read `phase1-spec.md` §7.2–§7.3. Execute **Session 1.4 only**: write `tests/differential.rs` (proptest ≥10,000 cases, `2 ≤ t ≤ n ≤ 8`, vs `frost-ed25519`, cross-verify both directions) and `tests/identifiable_abort.rs` (garbage partial → `Culprit`; wrong-`λ` partial → `Culprit`; honest set succeeds) for 2-of-3 and 3-of-5. Verify `cargo tree -e normal` shows `frost-ed25519` only in dev-deps. Commit, run checks, list changes, STOP.

**Session 1.5 prompt**
> Read `phase1-spec.md` §8 and `kickoff-amendment-1.md` §1. Execute **Session 1.5 only**: create the `legacy/` crate — the single-key Schnorr oracle (`open_session`, `sign`) with NO binding factor, unlimited concurrency, and the reduction doc-comment (threshold aggregate collapses to single-key). Add a smoke test (one session signs and verifies). Do not wire it into `frost-core`. Commit, run build + test, list changes, STOP. Phase 1 complete; verify DoD §9 item by item.
