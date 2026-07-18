# frost-ed25519-kit — Threat Model

This document describes the security assumptions, trust boundaries, adversary
model, and explicit non-goals of `frost-ed25519-kit`. Every security claim is
backed by either implementation or tests referenced throughout the document.
`frost-core` is a sans-IO library: it performs no I/O on the trust path and
provides no transport (see `ARCHITECTURE.md`).

The implementation follows RFC 9591 FROST (Ed25519, SHA-512) with trusted-dealer
or Pedersen DKG key generation, two-round signing, identifiable abort, and a
validated group layer. The runtime dependency graph consists of six crates and
the project is compiled with `#![forbid(unsafe_code)]`.

---

## 1. Trust boundaries — who holds what

| Role                                    | Holds                                                                          | Sees                                                             | Never sees                                                      |
| --------------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------- |
| **Participant `i`**                     | its signing share `s_i` (secret), its nonces `(d_i, e_i)` (secret, single-use) | the public key package, other participants' commitments/partials | another participant's `s_j` or nonces                           |
| **Dealer** (trusted-dealer keygen only) | the full secret polynomial `f`, hence the group secret `s = f(0)`              | everything it generates                                          | — (it is the trust assumption; eliminated by DKG)               |
| **DKG (no dealer)**                     | no single party holds `s`; each holds `s_i` only                               | the broadcast commitments + PoKs; each its own received shares   | the group secret `s` exists only implicitly across `≥ t` shares |
| **Coordinator**                         | nothing secret                                                                 | the commitment set, the message                                  | no shares, no nonces                                            |
| **Aggregator**                          | nothing secret                                                                 | commitments `(D_j, E_j)`, partials `z_j`, verifying shares `X_j` | the shares `s_j`, the nonces `(d_j, e_j)`                       |

The dealer is a trust assumption **only** in trusted-dealer mode and is retained
as a documented fallback; the Pedersen DKG removes it (no party ever holds `s`).

---

## 2. Adversary model & the sub-threshold guarantee

A coalition of **fewer than `t`** participants learns **nothing** about the group
secret. This is the Shamir information-theoretic property: `t-1` evaluations of a
degree-`(t-1)` polynomial are consistent with every possible constant term, so the
secret is perfectly hidden below threshold — not "computationally hard," _nothing_.

At **`≥ t`** participants, reconstruction of the group secret is an intended property
of the protocol — that is what the threshold _is_. A `≥ t` coalition reconstructing `s`
is not a vulnerability; it is the defined capability of any `t`-of-`n` scheme. Stated plainly
so it is not mistaken for a finding: there is no defense against a `≥ t` collusion,
and none is intended (see §11, out of scope).

---

## 3. Aggregator trust

The aggregator is **untrusted for confidentiality and integrity** and cannot learn
the key or forge:

- It sees each `z_i = d_i + ρ_i·e_i + λ_i·c·s_i` but not the nonces `(d_i, e_i)`, so
  it cannot solve for `s_i` (one equation, two unknowns per partial). It never holds
  a share.
- **What a malicious aggregator _can_ do:** refuse to aggregate (liveness, not
  safety), or mis-attribute blame. Mis-attribution is bounded by **identifiable
  abort**: before summing, the aggregator must verify each partial against its
  public verifying share `X_j` (`z_j·G == (D_j + ρ_j·E_j) + λ_j·c·X_j`); a bad
  partial yields `Culprit(id_j)` naming the _real_ offender, and only verified
  partials are summed (`sign::aggregate`, `tests/identifiable_abort.rs`).
- **What it _cannot_ do:** forge a signature, learn a share, or produce a valid
  aggregate from invalid partials — the final signature is checked under RFC 8032
  before return.

---

## 4. The ROS / concurrent-signing defense — the headline

The original threshold Schnorr implementation preserved under `legacy/` is
forgeable under concurrent signing. The included ROS demonstration
(`legacy/results/ros_forgery.txt`) shows a successful forgery using 256
concurrent sessions without knowledge of the secret key. The archived implementation is retained to provide a reproducible demonstration of the vulnerability.

The fix is FROST's **binding factor**. Each signer commits a _pair_ `(D_i, E_i)`,
and its effective per-session commitment is `R_i^eff = D_i + ρ_i·E_i` with
`ρ_i = H1(group_public ‖ H4(msg) ‖ H5(commitment_list) ‖ id)` — a hash of the
message _and the full commitment list_. The ROS solver needs each session to be a
homomorphic Schnorr response whose challenge is a function of `(R_i, msg)` alone, so
that it can pre-commit to a fixed linear combination of per-session challenges. Under
FROST the per-session commitment is not fixed until the messages are chosen, and the
moment they are chosen the commitments (hence `R*` and `c*`) move with them: the
linear system the solver requires **never exists**. The negative control
(`frost-core/tests/ros_resistance.rs`) runs the _same_ solver against FROST and
asserts `RosOutcome::NoSolution` — structurally, not as a failed-attempt count.

The same mechanism defeats **cross-session replay**: a partial valid in session A is
rejected in session B because the recomputed `ρ` and challenge bind it to A's exact
`(msg, commitment-set)` (`tests/adversarial.rs::cross_session_replay_is_rejected`).

---

## 5. Rogue-key resistance (DKG)

In the Pedersen DKG, each participant broadcasts a Schnorr **proof of knowledge** of
its constant term `a_{i,0}`: `μ_i·G == R_i + c_i·φ_{i,0}`, `c_i = H_dkg(i ‖ φ_{i,0}
‖ R_i)`. This prevents participants from advertising public commitments that they cannot
open with a matching secret polynomial, preventing the rogue-key attack described by
Gennaro, Jarecki, Krawczyk, and Rabin, in which a participant chooses its public contribution `φ_{j,0}`
as a function of the others' to bias the group key: without knowing the matching `a_{j,0}`
it cannot produce a valid PoK, and `part2` rejects it as `Culprit(j)` (`tests/dkg_adversarial.rs`, `dkg_pok_pin.rs`).
The PoK nonce is itself hedged (§7).

---

## 6. Small-subgroup / cofactor, and canonical-encoding enforcement

Edwards25519 has cofactor **8**: the curve group is `8·L` points, of which only the
prime-order `L`-subgroup is cryptographically sound. The group layer **rejects every
non-prime-order point at deserialization** (`GElement::from_compressed` returns
`NonPrimeOrderPoint` unless the point is torsion-free), so a small-subgroup point can
never enter a commitment, verifying share, or signature. This closes small-subgroup
confinement / invalid-curve attacks that a cofactor-8 curve otherwise invites
(`tests/adversarial.rs::gelement_rejects_bad_and_non_prime_order_points`, the fuzz
target `gelement_from_compressed`).

### 6.1 Canonical-encoding enforcement (RFC 8032 strict decoding)

Every point and scalar crossing the trust boundary must be its **canonical**
encoding; a non-canonical encoding is **rejected, never coerced**. For points this is
enforced in `GElement::from_compressed`: after decompression the point is re-encoded
and compared byte-for-byte to the input, and any mismatch returns
`InvalidPointEncoding` — _before_ the torsion check (`frost-core/src/group.rs`).
Scalars and identifiers decode only via `from_canonical_bytes`, which rejects any
encoding `≥ L` as `NonCanonicalScalar` rather than reducing it.

The vector this closes is **point/signature malleability**: a non-canonical `y ≥ p`
(e.g. `0xFF…FF`, which is `y = p + 1`) or a set sign bit on the `x = 0` point
decompresses — under a lenient decoder — to the _same_ group element as a canonical
encoding, so two distinct byte-strings would verify as the same signature.
`curve25519-dalek`'s `decompress()` is exactly such a lenient decoder: it silently
canonicalizes these inputs. The strict re-encode-and-compare rejects them. This is a
**deserialization malleability guard, not a key-recovery or forgery defense** — stated
at its exact severity, given the Ed25519/Solana positioning where signature
non-malleability is load-bearing.

How it was found: the **coverage-guided fuzz run** caught this where the random-input
bounded floor did not. The implementation now enforces RFC 8032 strict decoding by re-encoding
the decompressed point and rejecting any byte mismatch. Regression tests preserve
the original inputs that exposed the issue.

---

## 7. Hedged nonces

Both signing nonces and the DKG PoK nonce use the RFC 9591 hedged construction
`nonce = H3(random_bytes(32) ‖ encode(secret))`, so a weak or fully predictable RNG
_alone_ cannot cause nonce reuse — the failure class that leaked the PS3 ECDSA
signing key. Single use is additionally a **compile-time** guarantee: `SigningNonces`
is consumed by value and is neither `Clone` nor `Copy`
(`tests/adversarial.rs::nonce_single_use_is_a_compile_time_guarantee`).

---

## 8. Identifiable abort

Every cross-participant failure names the culprit, not merely "someone cheated":

- a bad **partial signature** → `Culprit(id)` before summing (§3);
- a bad **DKG PoK** or **VSS share** → `Culprit(j)` / `InvalidShare(j)` in `part2`/`part3`.

This allows callers to identify the offending participant and take application-specific
recovery actions.

---

## 9. DKG transport assumption

The DKG's round-2 messages are **secret-in-transit**: `round2::Package` carries one
participant's secret share `f_i(ℓ)` addressed to recipient `ℓ`. Unlike the
signing messages (which carry no secret), VSS _requires_ a private dealer→recipient
channel. **This library provides the share type's hygiene — zeroize-on-drop, a
redacting `Debug`, no `serde`, and a `serialize` that returns `Zeroizing` bytes — but
it does NOT provide the channel.** Delivering `round2::Package` over a **private,
authenticated channel** is the integrator's responsibility and is an explicit
assumption of the DKG's security. Sending these messages over an unauthenticated or public channel
compromises share confidentiality and falls outside the library's security guarantees.

---

## 10. Secret hygiene and its honest limit

Every secret type is structurally audited (`tests/zeroization_audit.rs`): the leaf
secrets (`SigningShare`, `SigningNonces`, and the crate-private `SecretPolynomial`)
are `ZeroizeOnDrop`; the DKG packages hold their secret only inside a zeroizing leaf,
so dropping a package wipes it; every secret type has a **redacting `Debug`** (proven
by formatting real instances and asserting the secret bytes are absent); and no
secret implements `serde::Serialize` — the crate has **no `serde` dependency at all**
(enforced by `deny.toml`), the sole exception being `round2::Package`'s hand-rolled,
`Zeroizing`-wrapped `serialize` for the private channel of §9.

**Honest limit:** verifying that a specific _freed memory page_ is actually scrubbed
requires inspecting freed memory, which needs `unsafe` — and the crate is
`#![forbid(unsafe_code)]`. The audit therefore proves the **types and traits** are
correct (zeroize-on-drop is wired, no secret is `Debug`/`Serialize`-leaked), **not**
that a particular physical page was zeroed. We name this boundary rather than imply a
guarantee the test does not provide.

---

## 11. Out of scope

The following are explicitly **not** provided; an integrator must account for them:

- **No `≥ t` collusion defense** — definitional (§2); a quorum can sign and
  reconstruct by design.
- **No transport security** — the library is sans-IO; it provides no channel,
  encryption, or authentication. The DKG round-2 private-channel assumption (§9) is
  the integrator's to satisfy.
- **No robust / restartable DKG** — the DKG is **abort-and-identify**, not
  complaint-and-continue (GJKR): a detected cheat aborts the run and names the
  culprit; it does not transparently continue with the honest subset. (This matches the behaviour of the reference implementation used during differential testing; see `ARCHITECTURE.md`.)
- **No side-channel hardening beyond `curve25519-dalek`** — constant-time scalar and
  point arithmetic come from the backend; the library adds no further timing,
  power, or fault-injection countermeasures.
- **Fuzzing honesty limit** — absence of a crash within a budget is not proof of
  total absence; the committed budget is reported as an exec count, not "clean." The
  coverage-guided run (**104,624,899 execs across six deserializers, 0 crashes
  post-fix**) is what _found_ the non-canonical point-encoding malleability vector
  §6.1 documents; the stable bounded floor (3,600,036 execs) is the CI-runnable
  version of the same harness (`fuzz/README.md`).
- **Zeroization honesty limit** — post-free memory scrub is unverifiable under
  `#![forbid(unsafe_code)]` (§10).
- **RNG quality** — hedged nonces (§7) defend against a _predictable_ RNG causing
  reuse, but key generation still requires a cryptographically secure RNG for
  unpredictability; a fully attacker-controlled RNG at keygen is out of scope.
