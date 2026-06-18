# frost-ed25519-kit — Phase 2 Specification: Verifiable Distributed Key Generation (Pedersen DKG)

**Companion to:** `kickoff-brief.md`, `kickoff-amendment-1.md`, `phase0-spec.md`, `phase1-spec.md`, and the current `CLAUDE.md`. Read all first.
**This is the complete, authoritative Phase 2 spec.** It covers a hand-rolled 3-round Pedersen DKG with a rogue-key-resistant proof of knowledge, identifiable abort on bad dealers, hedged PoK nonces, and the validation harness: a deterministic PoK-challenge pin, differential interop against `frost-ed25519`'s DKG in both directions, and a functional end-to-end gate (DKG → sign → verify).
**Audience:** Claude Code. Authoritative.

---

## 1. Phase 2 in one paragraph

Replace the trusted dealer's *trust assumption* with a distributed key generation in which no single party ever holds the group secret. Implement the FROST Pedersen DKG (Komlo–Goldberg §5; the protocol `frost-core`/`frost-ed25519` ship as `keys::dkg`) as three pure-function rounds over the **frozen** Phase 0/1 primitives: round 1 — each participant samples a degree-`(t-1)` polynomial, publishes a Feldman commitment and a Schnorr **proof of knowledge** of its constant term (the rogue-key defense); round 2 — each participant verifies every peer's PoK and commitment and emits one private secret share per recipient; round 3 — each participant verifies the shares it received against the senders' commitments, names any bad dealer, and sums to its signing share, deriving the same `group_public` and `verifying_shares` the trusted dealer produced. The DKG is a new *constructor* of the **unchanged** Phase 0 `KeyPackage` / `PublicKeyPackage` types — the Phase 1 signing path consumes its output without modification. There is no official RFC 9591 KAT for DKG (DKG is not normative in RFC 9591), so correctness rests on the same machinery that proved Phase 1: a deterministic pin on the one new hash-input encoding, differential interop against `frost-ed25519` both directions, and a functional DKG→sign→verify gate.

### 1.1 Frozen / reused
- **`group.rs`, `secret.rs`, `message.rs`, `vss.rs`, `sign.rs`, `verify.rs` are frozen.** The DKG reuses `vss::verify_share` and `vss::verifying_share` unchanged, the frozen `Identifier` validation, and the frozen group/secret layer. If the DKG appears to need a change to any frozen module, the DKG design is wrong — STOP and ask.
- **`keygen.rs` trusted-dealer is reused and retained** — as the documented fallback (§3), as the oracle for the reconstruction tests, and because Phase 0 made it the type contract. The DKG lives in a new `dkg.rs` and emits the identical `KeyPackage` / `PublicKeyPackage`.
- **`frost-core` gains exactly one shipped file: `dkg.rs`** (and one ciphersuite constant for the PoK challenge label). No new shipped dependency — `sha2` (approved Session 1.1) already covers the hash. `frost-ed25519`/`proptest`/`serde_json` remain dev-only.
- **`legacy/` is untouched.** The ROS solver is Phase 3.

---

## 2. Workspace additions & dependencies

```
frost-core/src/dkg.rs                  # NEW (shipped) — part1/part2/part3, PoK, identifiable abort
frost-core/src/ciphersuite.rs          # +1 constant: the DKG PoK challenge label (verify vs source)
frost-core/tests/dkg_pok_pin.rs        # NEW — deterministic PoK-challenge encoding pin (amendment §4 spirit)
frost-core/tests/dkg_differential.rs   # NEW — interop vs frost-ed25519 DKG, both directions + functional
frost-core/tests/dkg_adversarial.rs    # NEW — bad PoK, bad share names dealer, rogue key, id discipline
```

No change to the shipped dependency graph beyond the existing `sha2`. Re-verify after the phase: `cargo tree -e normal -p frost-core` shows `curve25519-dalek, rand_core, sha2, subtle, thiserror, zeroize` only. `frost-ed25519`, `proptest`, `serde_json` remain dev-only.

---

## 3. The DKG decision (Principal Architect call)

**Build the Pedersen DKG.** Rationale: Phase 1 proved the team can hand-roll a frost ciphersuite against the `frost-ed25519` oracle with byte-level localization; "no trusted dealer, with a rogue-key proof of knowledge" is exactly the adversarial-reasoning signal the target audience probes; and the DKG output is a drop-in for the frozen signing path.

**Trust model the DKG actually achieves (state this in `ARCHITECTURE.md` and, in Phase 3, `THREAT-MODEL.md`):** an honest *majority is not required*; the scheme is secure against any coalition of `< t` participants. The DKG defends **secrecy** unconditionally below threshold and defends **integrity at keygen** against rogue-key biasing via the PoK. It is **abort-and-identify, not robust**: a malicious dealer cannot forge or bias the key, but can cause the DKG to abort — and when it does, the protocol **names the culprit** (§6). Restart without the named party is an operator action, out of scope for the library.

**Supersession of the brief's "complaint round."** `kickoff-brief.md` §3.2 wrote "complaint round." That is overridden here in favor of abort-and-identify, for a stated reason: a full GJKR complaint-and-disqualify-and-continue protocol diverges from the `frost-ed25519` DKG and would forfeit the differential-interop gate (§8.2) that made Phase 1 safe. Robust GJKR-style continuation is explicit future work, recorded in `ARCHITECTURE.md`'s rejected-alternatives table. This supersession is the DKG analogue of the Session 1.1 rho-prefix correction: follow the verifiable ecosystem, not the shorthand.

**Scope-cut path (use only if part1 PoK comprehension stalls):** ship trusted-dealer keygen as the documented v1 with the trust assumption stated plainly, move the DKG to a later phase, and say so honestly in the README. Do not ship a half-verified DKG to look decentralized. The default is to build it.

---

## 4. The protocol — `dkg.rs`

Three rounds, mirroring the `frost-core` `keys::dkg` API so the differential (§8.2) is clean. All notation additive (Ed25519).

```rust
pub mod round1 {
    /// Kept private by the participant. Holds the secret polynomial. Zeroize-on-drop, non-Debug.
    pub struct SecretPackage { /* f_i coeffs (Zeroizing), id, threshold, max_signers */ }
    /// Broadcast to all. Carries NO secret. Serializable.
    pub struct Package { pub commitments: Commitments /*φ_{i,0..t-1}*/, pub pok: ProofOfKnowledge /*(R_i, μ_i)*/ }
}

/// Round 1: sample f_i (degree t-1), commit φ_{i,k}=a_{i,k}·G, prove knowledge of a_{i,0}.
pub fn part1(id: Identifier, threshold: u16, max_signers: u16, rng: &mut impl rand_core::CryptoRng)
    -> Result<(round1::SecretPackage, round1::Package), Error>;

pub mod round2 {
    /// Kept private. Holds f_i + the participant's own share. Zeroize-on-drop, non-Debug.
    pub struct SecretPackage { /* ... */ }
    /// One secret share f_i(ℓ) addressed to recipient ℓ. SECRET-IN-TRANSIT (see §7):
    /// Zeroize-on-drop, redacting Debug, serializable ONLY for transport over a private+authenticated channel.
    pub struct Package { /* recipient id + Zeroizing<scalar> */ }
}

/// Round 2: verify every peer's PoK and commitment; emit one private share per OTHER participant.
/// On any invalid PoK/commitment, return Err(Culprit(dealer_id)) — names the bad dealer. (§6)
pub fn part2(
    secret: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error>;

/// Round 3: verify each received share against its sender's commitment (frozen vss::verify_share);
/// on a bad share return Err(Culprit(dealer_id)). Then sum to s_i, derive group_public and all verifying_shares.
pub fn part3(
    secret: &round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    round2_packages: &BTreeMap<Identifier, round2::Package>, // the shares addressed to me
) -> Result<(KeyPackage, PublicKeyPackage), Error>;
```

**Round-1 internals (the only new crypto):**
- Sample `f_i` with `t` coefficients (degree `t-1`); zeroize the coefficients on drop.
- `φ_{i,k} = a_{i,k}·G` for `k = 0..t-1`. `φ_{i,0}` is the participant's public contribution.
- **Proof of knowledge of `a_{i,0}` (rogue-key defense):** hedged nonce `k_i = H3(random_bytes(32) ‖ encode(a_{i,0}))` (amendment §3, applied to the PoK nonce); `R_i = k_i·G`; challenge `c_i = H_dkg(id_i ‖ CONTEXT_STRING ‖ φ_{i,0}_enc ‖ R_i_enc)` — **verify the exact label and input order against `frost-ed25519` 2.2.0 source before writing the body** (§5); response `μ_i = k_i + a_{i,0}·c_i`. The hedged `k_i` is consumed/zeroized immediately.

**Round-2 internals:**
- For each peer `j`: recompute `c_j`, verify `μ_j·G == R_j + c_j·φ_{j,0}`. On failure → `Err(Culprit(j))`.
- Verify each peer commitment is well-formed (every `φ_{j,k}` a valid prime-order point — frozen group layer rejects otherwise).
- Compute `f_i(ℓ)` for every recipient `ℓ` (including `i` itself); package the share addressed to each.

**Round-3 internals:**
- For each received share `f_j(i)`: `vss::verify_share(my_id, share, round1_packages[j].commitments)` (frozen). On failure → `Err(Culprit(j))`.
- `s_i = Σ_j f_j(i)` (Zeroizing accumulation); `group_public = Σ_j φ_{j,0}`; `verifying_shares[ℓ] = Σ_j vss::verifying_share(ℓ, commitments_j)` for all `ℓ` (frozen, summed). Return `KeyPackage { id, signing_share: s_i, verifying_share: verifying_shares[i] }` and `PublicKeyPackage { group_public, verifying_shares, threshold }` — the **identical Phase 0 types**.

---

## 5. Verify-never-assume (the §3-of-Phase-1 discipline, applied to the PoK)

The DKG introduces exactly one new hash-input encoding: the PoK challenge `H_dkg`. This is precisely the one-byte-prefix risk surface that the Session 1.1 rho correction exposed. Before writing `part1`'s body:
- Locate the PoK challenge computation in `frost-ed25519` 2.2.0 / `frost-core` (`keys::dkg::part1` and the `compute_proof_of_knowledge` / challenge helper).
- Pin the exact: domain label (is it `"dkg"`? a different constant?), the inclusion and order of `identifier`, `CONTEXT_STRING`, `φ_{i,0}`, and `R_i`, and the reduction (wide mod-L over SHA-512).
- Record each as a named constant in `ciphersuite.rs` with a `// frost-ed25519 2.2.0 <file>:<line>` provenance comment, exactly as Session 1.1 did for H1–H5.
- **The deterministic pin test (§8.1) is the guard** — it fails at the PoK challenge, with localization, if the encoding deviates, instead of surfacing as an unattributable DKG verification failure downstream.

---

## 6. Identifiable abort (amendment §2, generalized to DKG)

A DKG that fails must name the party that caused it — the keygen analogue of Phase 1's partial-signature abort, and the same flagship requirement (a secret broker must know *which component* misbehaved, not merely that keygen failed).
- **Bad PoK or malformed commitment** (round 2): `Err(Culprit(dealer_id))`.
- **Share inconsistent with its commitment** (round 3): `Err(Culprit(dealer_id))`.
- **Rogue-key attempt** — a participant broadcasting `φ_{j,0}` without a valid PoK (e.g., a key chosen as a function of others' contributions to bias `group_public`) is rejected at round 2 as `Culprit(j)`; the PoK is what forces every contributor to *know* its secret, defeating the Gennaro et al. biasing attack. This is tested (§8.3), and the defense is named in `ARCHITECTURE.md`.

`Error::Culprit(Identifier)` already exists (Phase 0 `error.rs`); reuse it. No new error variant unless a DKG-specific case has no honest mapping — if one is needed, add it in `error.rs` and note that `error.rs` was Phase-0-frozen for *signing*; a DKG addition is a documented, additive exception, not a contract change to existing variants.

---

## 7. Secret-in-transit — the one principled deviation, stated plainly

Phase 0 froze `message.rs` with "no `Serialize` on a secret type." The DKG forces a bounded exception, and it must be surfaced, not smuggled:

`round2::Package` carries a secret share `f_i(ℓ)` that **must** cross a channel to reach recipient `ℓ`. It is therefore serializable — but it is **not** a `message.rs` type (frozen and untouched); it is a `dkg.rs` type that:
- is `ZeroizeOnDrop` and has a **redacting `Debug`** (no key bytes),
- is transmitted **only over a private, authenticated channel** — this is the DKG's stated transport trust assumption, recorded in `ARCHITECTURE.md` now and `THREAT-MODEL.md` in Phase 3,
- never appears in a log, and is consumed/zeroized in `part3`.

This differs from the signing message types (which carry no secrets) by necessity: VSS *requires* a private dealer→recipient channel. Stating the assumption is the honest move; pretending the share never travels would be the dishonest one. A reviewer evaluates whether you *named* the trust boundary — name it.

---

## 8. The validation harness

There is **no official RFC 9591 KAT for DKG** (DKG is not normative in RFC 9591). State this in the test module header. Correctness rests on the three gates below, in the Phase 1 spirit: pin the new encoding deterministically, prove interop against the oracle both directions, and prove the functional end-to-end property.

### 8.1 `tests/dkg_pok_pin.rs` — deterministic PoK-challenge pin (amendment §4 spirit)
For a fixed `(identifier, φ_{i,0}, R_i)`, assert `frost-core`'s `c_i` equals the value `frost-ed25519` computes for the same inputs (call its challenge helper, or reconstruct it from its source-verified encoding). This is the single new encoding; pin it **before** the full-DKG tests so a deviation localizes here, not three rounds downstream. Also assert PoK self-consistency: `μ_i·G == R_i + c_i·φ_{i,0}` for an honestly generated proof.

### 8.2 `tests/dkg_differential.rs` — interop vs `frost-ed25519`, both directions + functional
- **Direction A (our packages, their verifier):** run `frost-core` `part1` for a participant; serialize its `round1::Package`; confirm `frost-ed25519` deserializes it and accepts the PoK + commitment (drive `frost-ed25519`'s `part2` with our `round1` packages as input and assert it does not reject on verification).
- **Direction B (their packages, our verifier):** the reverse — `frost-ed25519` `part1` packages deserialize into `frost-core` and pass our round-2 PoK/commitment verification.
- **Functional, full `frost-core` DKG:** run a complete `frost-core` DKG for 2-of-3 and 3-of-5; then (i) reconstruct the group secret from `t` signing shares in-test and assert `·G == group_public`; (ii) assert every `verifying_share` matches `vss::verifying_share` over the summed commitments; (iii) feed the DKG `KeyPackage`s into the **frozen Phase 1** `commit`/`sign`/`aggregate`, and verify the signature under both `verify.rs` and `frost-ed25519`'s verifier. This proves the DKG output is a valid FROST key, end to end.
- A `proptest` wrapper over `2 ≤ t ≤ n ≤ 8` for the functional path (≥1,000 cases is sufficient here — the DKG is heavier than signing; the interop directions run on fixed small sets).

**On byte-for-byte DKG agreement:** unlike Phase 1's nonces, the DKG draws polynomial coefficients *and* a PoK nonce per participant, so matching `frost-ed25519`'s exact RNG draw order for byte-identical packages is brittle and couples our code to the oracle's internals. It is an **optional** stretch, not a gate. The required differential is interop (both directions) + functional. State this choice in the test header — it is the honest, robust gate, and the reasoning is the signal.

### 8.3 `tests/dkg_adversarial.rs`
- **Bad PoK** → `part2` returns `Culprit(j)` (2-of-3 and 3-of-5); the honest set, run without `j`, completes.
- **Bad share** (a dealer sends `f_j(i)` inconsistent with its broadcast commitment) → `part3` returns `Culprit(j)`.
- **Rogue key** (a commitment `φ_{j,0}` with an invalid/absent PoK) → rejected at `part2` as `Culprit(j)`.
- **Identifier discipline** (amendment §5, via the frozen layer): a DKG entered with a zero or duplicate identifier in the participant set is rejected (`ZeroIdentifier` / `DuplicateIdentifier`).
- **Hedged PoK nonce** (amendment §3): a deterministic-RNG test — same RNG state, different `a_{i,0}` → different `k_i`/`R_i` — proving the share entropy is mixed into the PoK nonce (the Phase 1 §6 pattern, applied to the PoK).

---

## 9. Phase 2 Definition of Done

1. Frozen modules byte-for-byte unchanged: `group.rs`, `secret.rs`, `message.rs`, `vss.rs`, `sign.rs`, `verify.rs`. `keygen.rs` trusted-dealer unchanged and retained. `git diff` confirms.
2. `dkg.rs` implements `part1`/`part2`/`part3` per §4, emitting the **identical** Phase 0 `KeyPackage` / `PublicKeyPackage` types; the Phase 1 signing path consumes DKG output unchanged.
3. Rogue-key PoK present, with the hedged PoK nonce (§4, amendment §3); PoK nonce single-use/zeroized.
4. **PoK challenge pin** (§8.1) green: `frost-core`'s `c_i` matches `frost-ed25519` for fixed inputs; PoK self-consistency holds. The PoK label/encoding carries source provenance in `ciphersuite.rs`.
5. **Differential interop** (§8.2) green both directions; **functional** DKG→reconstruct, verifying-share match, and DKG→sign→verify (under both verifiers) green for 2-of-3 and 3-of-5, with the proptest wrapper.
6. **Identifiable abort** (§6, §8.3): bad PoK, bad share, and rogue key each yield `Culprit(dealer_id)`; the honest set completes without the named party.
7. **Identifier discipline** (§8.3): zero/duplicate identifiers in the participant set rejected via the frozen layer.
8. **Secret-in-transit** (§7): `round2::Package` is `ZeroizeOnDrop`, redacting `Debug`, transported-only-private; the trust assumption is recorded in `ARCHITECTURE.md`. No secret in any broadcast (`round1::Package`) type.
9. Shipped graph unchanged (still Phase-0-deps + `sha2`); `cargo tree -e normal -p frost-core` proves `frost-ed25519`/`proptest`/`serde_json` dev-only; `#![forbid(unsafe_code)]` intact.
10. The "no official RFC 9591 DKG KAT" fact is stated in the test headers, and the chosen gates (interop + functional) are justified there.
11. `cargo build`, `cargo clippy --all-targets -D warnings`, `cargo test` clean workspace-wide.
12. **Self-audit (comprehension gate):** the owner can, from memory, (a) verify `μ_j·G == R_j + c_j·φ_{j,0}` and state why the PoK stops the rogue-key biasing attack, and (b) explain why the DKG is abort-and-identify rather than robust, and what that costs.

No ROS solver, no threat-model prose, no README rewrite this phase — those are Phases 3–4. The brief's "complaint round" is superseded per §3.

---

## Appendix A — `CLAUDE.md` update for Phase 2

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md        — strategy, audit, architecture, DoD
- docs/specs/kickoff-amendment-1.md  — adversarial/crypto upgrades (binding)
- docs/specs/phase0-spec.md          — demolition, sans-IO core, group layer (FROZEN)
- docs/specs/phase1-spec.md          — FROST signing + KAT/differential (FROZEN)
- docs/specs/phase2-spec.md          — CURRENT: Pedersen DKG, PoK, identifiable abort

## Hard rules (Phase 2 additions)
10. group/secret/message/vss/sign/verify are FROZEN. keygen trusted-dealer is retained.
    The DKG is a NEW constructor (dkg.rs) of the UNCHANGED KeyPackage/PublicKeyPackage types.
11. The DKG PoK challenge is the one new encoding: VERIFY label + input order against
    frost-ed25519 2.2.0 source; pin it deterministically (dkg_pok_pin) BEFORE the full DKG.
12. DKG is abort-and-identify: bad PoK / bad share / rogue key -> Culprit(dealer_id).
    "complaint round" from the brief is SUPERSEDED (matches the frost-ed25519 oracle).
13. round2 shares are SECRET-IN-TRANSIT: ZeroizeOnDrop, redacting Debug, private+authenticated
    channel only, documented as the DKG trust assumption. No secret in any broadcast type.
14. PoK nonce is hedged H3(random || encode(a_0)) and single-use. No official RFC DKG KAT
    exists — correctness = PoK pin + differential interop (both directions) + functional.
```

## Appendix B — Claude Code execution plan (Phase 2)

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 2.1 | Round 1 + PoK + pin | `ciphersuite` PoK constant (source-verified), `dkg.rs` `part1` (hedged PoK), `tests/dkg_pok_pin.rs` | PoK pin matches `frost-ed25519`; PoK self-consistent; frozen modules untouched |
| 2.2 | Round 2 + 3 + abort | `dkg.rs` `part2`/`part3` with `Culprit` on bad PoK/share; `round2::Package` secret-in-transit type | a full `frost-core` 2-of-3 DKG produces a `KeyPackage`/`PublicKeyPackage` |
| 2.3 | Differential + functional + adversarial | `tests/dkg_differential.rs`, `tests/dkg_adversarial.rs` | interop both directions; DKG→sign→verify green; abort names culprit; DoD §9 verified |

**Session 2.1 prompt**
> Read `phase2-spec.md` §1–§5 and `kickoff-amendment-1.md` §3–§5. Execute **Session 2.1 only**: locate the DKG PoK challenge computation in `frost-ed25519` 2.2.0 source, add its label/encoding to `ciphersuite.rs` as named constants with source provenance, and implement `dkg.rs` `part1` — degree-`(t-1)` polynomial (zeroized), Feldman commitments, and the rogue-key PoK with a hedged nonce `H3(random ‖ encode(a_0))`. Write `tests/dkg_pok_pin.rs` pinning `c_i` against `frost-ed25519` and asserting `μ_i·G == R_i + c_i·φ_{i,0}`. Touch no frozen module. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 2.2 prompt**
> Read `phase2-spec.md` §4, §6, §7. Execute **Session 2.2 only**: implement `part2` (verify every peer PoK + commitment → `Culprit(j)` on failure; emit one private share per recipient) and `part3` (verify each received share with the frozen `vss::verify_share` → `Culprit(j)` on failure; sum to `s_i`; derive `group_public` and all `verifying_shares`; return the unchanged Phase 0 `KeyPackage`/`PublicKeyPackage`). Add `round2::Package` as a secret-in-transit type (ZeroizeOnDrop, redacting Debug, serializable for private transport). A full in-process 2-of-3 DKG must produce a valid key package set. Touch no frozen module. Commit, run checks, list changes, STOP.

**Session 2.3 prompt**
> Read `phase2-spec.md` §8–§9. Execute **Session 2.3 only**: write `tests/dkg_differential.rs` (interop both directions vs `frost-ed25519` DKG; functional full DKG for 2-of-3 and 3-of-5 — reconstruct group key in-test, verifying-share match, and DKG→frozen-`sign`→`verify` cross-verified under `frost-ed25519`; proptest wrapper `2 ≤ t ≤ n ≤ 8`) and `tests/dkg_adversarial.rs` (bad PoK → Culprit, bad share → Culprit, rogue key → Culprit, zero/duplicate id rejected, hedged-PoK-nonce determinism). State the no-official-DKG-KAT fact in the test headers. Verify `cargo tree -e normal -p frost-core` keeps `frost-ed25519` dev-only. Commit, run build + clippy -D warnings + test, list changes, verify DoD §9 item by item, STOP. Phase 2 complete.
