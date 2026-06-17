# frost-ed25519-kit — Kickoff Amendment 1 (Adversarial & Cryptographic Rigor)

**Amends:** `docs/specs/kickoff-brief.md`. Does not replace it. Read the brief first, then apply these five upgrades where indicated.
**Source:** Chief Architect directive, Repo 4. **Authority:** binding. **Audience:** Claude Code + the phase specs.
**One line:** these upgrades move the repo from "a correct FROST implementation" to "a person who understands the adversary." Upgrades 1 and 2 carry most of that weight.

---

## Where each upgrade lands

| # | Upgrade | Brief section affected | Phase | Surface |
|---|---|---|---|---|
| 1 | ROS attack, specified precisely | §5 (harness), §6 DoD #4 | **3** | `legacy/`, `tests/ros_resistance.rs` |
| 2 | Partial-sig verification + identifiable abort | §3.1, §4.6, §5 | **1** | `keygen.rs` (P0 hook), `sign.rs`, `verify.rs`, `tests/identifiable_abort.rs` |
| 3 | Hedged nonce generation | §4.6 | **1** | `sign.rs`, `THREAT-MODEL.md` |
| 4 | KAT the intermediates first | §5, §6 DoD #2 | **1** | `tests/rfc9591_kat.rs` (ordering) |
| 5 | Identifier domain discipline | §1.7, §4.5 | **0** | `group.rs`, `tests/identifiers.rs` |

---

## 1. ROS attack — specify it precisely or it proves nothing (Phase 3)

"Implement the concurrent-session forgery" produces a strawman. The construction is exact:

**Attack target.** A clean in-process reimplementation of the legacy scheme's *math* in `legacy/` — never the old HTTP code. Oracle API:
```rust
// legacy/src/oracle.rs — the construction the repo used to ship, reduced to its core.
pub struct NaiveSchnorrOracle { /* holds the group secret s, X = s·G */ }
impl NaiveSchnorrOracle {
    pub fn open_session(&mut self) -> (SessionId, /* R_i = */ CompressedEdwardsY); // r_i fresh, R_i = r_i·G
    pub fn sign(&mut self, s: SessionId, msg: &[u8]) -> /* z_i = */ Scalar;        // z_i = r_i + H(R_i‖X‖msg)·s
    // unlimited concurrent open sessions; no binding factor anywhere.
}
```
**Reduction (state this in the oracle doc-comment and the writeup).** The legacy threshold aggregate is `z = Σ z_i = (Σ r_i) + c·(Σ λ_i s_i) = R + c·s`, where `s` is the group secret. The threshold scheme therefore reduces to single-key concurrent Schnorr for the purpose of this attack. The oracle models that single key directly. Attacking the full multi-party transcript is unnecessary and would obscure the result — do not.

**The attack.** The polynomial-time ROS solver of Benhamouda–Lefranc–Loss–Orsini–Raykova (2020), "On the (in)security of ROS." Open `ℓ ≥ 253` concurrent sessions (one per bit of the ~2^252 edwards25519 scalar-field order, plus slack; use `ℓ = 256`). Collect `R_1..R_ℓ`. Using the binary-decomposition trick, choose each session's message *after* seeing all `R_i` so that the forged challenge for a fresh target message decomposes as a known linear combination of the per-session challenges. Close the sessions, aggregate `(R*, z*)` on a message **no honest session ever signed**.

**Committed success criterion (the artifact).**
- The forged signature verifies under the group key `X`.
- The forged message is provably outside the signed set (assert it).
- Session count and wall-clock committed, benchmark-style: `ℓ=256 sessions, forgery in {X} ms` written to `legacy/results/ros_forgery.txt`. **A forgery in milliseconds against the construction the repo used to ship is the most senior single artifact in the portfolio.**

**The negative control must explain itself.** Running the same solver against FROST fails *by construction*, which proves nothing unless the `ros_resistance.rs` doc-comment states why: the binding factor `ρ_i = H1(msg_hash ‖ commitment_list_hash ‖ identifier_i)` is a function of the message and the full commitment list, so the adversary cannot know the challenge coefficients before fixing the messages — the linear system the ROS solver requires never exists. The self-audit gate (DoD §11) tests that the owner can reproduce this argument from memory.

---

## 2. Partial-signature verification + identifiable abort (Phase 1)

The brief omitted verification shares. Without them, an aggregate-verify failure says *someone* cheated, not *who* — useless for a secret broker.

**Keygen hook (Phase 0).** `keygen` emits, per participant, a public **verifying share** `X_i = s_i·G`, derived from the aggregated VSS commitments — **no new secret material** (`X_i` is the public commitment polynomial evaluated at `identifier_i`). This is added to Phase 0's `PublicKeyPackage` so Phase 1 has it without a keygen change. (See P0 spec §6.)

**Aggregator (Phase 1).** Before summing, verify each partial:
```
z_i·G  ==  (D_i + ρ_i·E_i)  +  (λ_i · c · X_i)
```
On failure, return `Err(Error::Culprit(identifier_i))` — name the participant. Only sum verified partials.

**Adversarial test (`tests/identifiable_abort.rs`).** A participant submits a garbage `z_i`; the aggregator returns `Culprit(that_id)` and the honest set is unaffected.

**Flagship mapping (README).** A sandbox secret broker must know *which component* misbehaved, not merely that the signing operation failed — identifiable abort is the difference between "evict node 3" and "halt the broker."

---

## 3. Hedged nonce generation (Phase 1)

"Unpredictable, single-use" is necessary but under-specified. Mandate the RFC 9591 hedged construction:
```
nonce = H3(random_bytes(32) ‖ encode(secret_share))
```
so a weak or compromised RNG *alone* cannot cause nonce reuse — the failure class that broke the PS3 ECDSA signing key. One line of code, one sentence in `THREAT-MODEL.md`, senior signal out of all proportion to cost. Both `d_i` (hiding) and `e_i` (binding) nonces use it.

---

## 4. KAT the intermediates first (Phase 1 — test ordering, not a design change)

RFC 9591 publishes intermediate values, not just the final signature. `tests/rfc9591_kat.rs` MUST assert them in this order, each gating the next:
1. per-signer **binding factors** `ρ_i`
2. **group commitment** `R`
3. per-signer **partial signatures** `z_i`
4. **final signature** `(R, z)` byte-for-byte

Rationale: a hand-rolled `ρ` preimage that deviates by one length prefix will be internally self-consistent, pass every differential property you invent, and fail only at the final byte-for-byte check with zero localization. Intermediate KATs are the bisection that makes hand-rolling survivable. The exact `contextString`, domain labels, and commitment-list encoding are **verified against RFC 9591 and the installed `frost-ed25519` source** — never assumed; these tests are the guard.

---

## 5. Identifier domain discipline (Phase 0)

Participant identifiers are **nonzero** scalars. `group.rs` deserialization MUST reject:
- the **zero** identifier — `x = 0` is the secret's own coordinate; a share there *is* the secret, and it breaks the protocol's domain assumption.
- **duplicate** identifiers within a set — duplicates make a Lagrange denominator `(x_i − x_j) = 0` (division by zero) or make two shares interpolate inconsistently.

Adversarial tests (`tests/identifiers.rs`) prove rejection of both. This is the edge a fuzzer finds in public; a spec line prevents it for free.

---

## Net effect on the Definition of Done (brief §6)

Add to the DoD:
- **§6.4 (revised):** the ROS forgery succeeds against `legacy/` per §1 with `ℓ`, wall-clock, and out-of-set proof committed; the negative-control argument is in `ros_resistance.rs`.
- **§6.2a (new):** intermediate KATs (`ρ_i`, `R`, `z_i`) pass before the final-signature KAT.
- **§6.6a (new):** zero and duplicate identifiers are rejected at deserialization, with adversarial tests.
- **§6.6b (new):** every partial is verified against its `X_i` before aggregation; a bad partial yields `Culprit(id)`, proven by test.
- **§6.5a (new):** nonces use the hedged `H3(random ‖ secret)` construction; stated in the threat model.
