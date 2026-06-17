# frost-ed25519-kit — Phase 0 Specification: Demolition, sans-IO Core, Validated Group Layer

**Companion to:** `docs/specs/kickoff-brief.md`, `docs/specs/kickoff-amendment-1.md`. Read both first.
**This is the complete, authoritative Phase 0 spec.** It covers the workspace demolition, the `frost-core` sans-IO foundation, the validated constant-time group layer, the secret-hygiene types, Feldman VSS, trusted-dealer keygen (including the public verifying shares Phase 1 needs), and the reconstruction + identifier-discipline tests.
**Audience:** Claude Code. Authoritative. This is the foundation phase.

---

## 1. Phase 0 in one paragraph

Delete the distributed shell (`orchestrator`, `node`, `store`, `nodeDb`) and the Solana/DB/HTTP dependency mass, purge the committed secret from history, and stand up a single `#![forbid(unsafe_code)]` library crate whose trust-critical path has no I/O. Build the validated, constant-time group layer (`group.rs`), the secret-hygiene types (`secret.rs`), the error model (`error.rs`), the transport-agnostic message types (`message.rs`), the Feldman VSS primitives (`vss.rs`), and trusted-dealer keygen (`keygen.rs`) that emits both secret shares and the public verifying shares `X_i = s_i·G`. The green gate is a reconstruction test (any `t` reconstruct, any `t-1` cannot) at 2-of-3 and 3-of-5, plus identifier-discipline tests. After this phase the sans-IO boundary and the `group`/`secret`/`message`/`vss` modules **freeze**.

### 1.1 Frozen / reused
- **The sans-IO boundary is law from here on.** No `tokio`, `reqwest`, `diesel`, Postgres, or `solana-*` in `frost-core`, ever. If signing later appears to need I/O in the core, the design is wrong — STOP and ask.
- **`group.rs`, `secret.rs`, `message.rs`, `vss.rs` freeze after Phase 0.** If Phase 1 signing appears to need a change to any of them, the signing design is wrong — STOP and ask.
- **`keygen.rs` is stable but not frozen:** Phase 2 adds Pedersen DKG *behind the same `SecretShare` / `VerifyingShare` / `PublicKeyPackage` types*. The types defined here are the contract; the trusted-dealer body is the v1 implementation.

---

## 2. Workspace demolition & dependencies

### 2.1 Delete (commit as the first change, with `git rm`)
```
orchestrator/   node/   store/   nodeDb/
```
Purge `nodeDb/.env` (committed DB creds) **from git history**, not just the working tree: `git filter-repo --path nodeDb/.env --invert-paths` (or BFG). Force-push to a clean history. Rotate the credential out of habit even though it is a local dev password — the discipline is the point. Remove the absolute `diesel.toml` migration path along with the crates.

### 2.2 Target workspace
```
frost-ed25519-kit/
  Cargo.toml                  # workspace; lints.workspace forbids unsafe
  frost-core/
    Cargo.toml
    src/
      lib.rs                  # #![forbid(unsafe_code)]; pub re-exports; crate docs
      group.rs                # validated CT (de)serialization — FROZEN after P0
      secret.rs               # Zeroizing secret types, single-use nonces — FROZEN after P0
      error.rs                # Error enum (incl. Culprit, defined now for P1)
      message.rs              # transport-agnostic wire types — FROZEN after P0
      vss.rs                  # Feldman commitments + verification — FROZEN after P0
      keygen.rs               # trusted-dealer keygen (+ verifying shares); Pedersen in P2
    tests/
      reconstruction.rs       # P0 green gate
      identifiers.rs          # amendment §5
  docs/
    specs/                    # this file + the brief + amendment
  README.md                   # one-line placeholder this phase; rewritten in P4
```

### 2.3 Dependency allowlist (Phase 0 — nothing else)
```toml
curve25519-dalek = { version = "4", features = ["zeroize", "rand_core"] }
zeroize          = { version = "1", features = ["zeroize_derive"] }
rand_core        = "0.6"
subtle           = "2"      # constant-time equality / choice
thiserror        = "2"      # error derive only; no runtime cost
# dev-dependencies:
rand             = "0.8"    # test RNG only
hex              = "0.4"    # KAT/test vector decoding only
```
No `serde` yet unless `message.rs` needs it for tests; if added, it is `derive` only and **never** applied to a secret type. `#![forbid(unsafe_code)]` at the crate root and `unsafe_code = "forbid"` in workspace lints.

---

## 3. `group.rs` — validated, constant-time group layer (FROZEN after P0)

Wrap dalek so that **every value crossing the trust boundary is validated on construction.** Raw `Scalar`/`EdwardsPoint` never appear in public APIs of higher modules.

```rust
/// A canonical scalar in [0, L). Constructed only via validated decoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GScalar(Scalar);

impl GScalar {
    /// Reject non-canonical encodings — NEVER reduce mod L. (Amendment: reject, never coerce.)
    pub fn from_canonical_bytes(b: [u8; 32]) -> Result<Self, Error>;
    pub fn to_bytes(&self) -> [u8; 32];
    // arithmetic delegates to dalek (constant-time): add, sub, mul, invert.
}

/// A point validated to be in the prime-order subgroup (cofactor-clean).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GElement(EdwardsPoint);

impl GElement {
    /// Decompress, then REJECT if not torsion-free (small-subgroup / cofactor attack guard).
    pub fn from_compressed(b: [u8; 32]) -> Result<Self, Error>; // None decompress -> Err; !is_torsion_free -> Err
    pub fn to_compressed(&self) -> [u8; 32];
    pub fn generator() -> Self;                // ED25519_BASEPOINT_POINT
    // add, scalar_mul (CT via dalek).
}

/// A participant identifier: a NONZERO scalar. (Amendment §5.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Identifier(GScalar);

impl Identifier {
    pub fn from_canonical_bytes(b: [u8; 32]) -> Result<Self, Error>; // zero -> Err(ZeroIdentifier)
    /// Convenience for small integer ids used in keygen/tests.
    pub fn try_from_u64(x: u64) -> Result<Self, Error>;             // 0 -> Err(ZeroIdentifier)
    pub fn as_scalar(&self) -> GScalar;
}

/// Validate that a set of identifiers contains no duplicates. (Amendment §5.)
pub fn validate_identifier_set(ids: &[Identifier]) -> Result<(), Error>; // dup -> Err(DuplicateIdentifier)
```

**Hard rules:**
- `from_canonical_bytes` for scalars uses dalek's canonical check (`Scalar::from_canonical_bytes` returning `CtOption`); a non-canonical encoding is `Err(NonCanonicalScalar)`, **never** silently reduced.
- `GElement::from_compressed` rejects non-decompressable bytes AND points failing `is_torsion_free()`.
- Equality is constant-time (`subtle`) where the inputs may be secret-derived.
- This module is the only place raw dalek types are touched.

---

## 4. `secret.rs` — secret hygiene types (FROZEN after P0)

```rust
/// A signing share s_i. Zeroized on drop. No Debug. Never serialized to a wire type.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningShare(/* Zeroizing<Scalar-bytes or GScalar> */);
// impl: NO #[derive(Debug)]; NO Serialize. Explicit `Debug` prints "SigningShare(<redacted>)".

/// A single-use nonce pair (hiding d_i, binding e_i). Consumed BY VALUE when used. (P1 fills the body.)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningNonces { /* d, e: zeroizing scalars */ }
// The type system enforces single use: `into_partial(self, ...)` consumes it; no Clone, no Copy.

/// Polynomial coefficients during keygen — zeroized after shares are derived.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretPolynomial { /* Zeroizing<Vec<Scalar>> */ }
```

**Hard rules:**
- Every secret type: `ZeroizeOnDrop`, no `Clone`/`Copy` unless unavoidable, **no `Debug` derive** (hand-write a redacting `Debug`), **no `Serialize`**.
- A test (`tests/identifiers.rs` or a dedicated `hygiene` test) asserts the redacting `Debug` does not contain key bytes.
- `SigningNonces` is consumed by value at use; reuse is a compile error, not a runtime check. This is upgrade 2.3's enforcement surface (the hedged *derivation* lands in P1; the single-use *type* lands now).

---

## 5. `error.rs` — fallible everywhere

```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("non-canonical scalar encoding")] NonCanonicalScalar,
    #[error("point not in prime-order subgroup")] NonPrimeOrderPoint,
    #[error("invalid point encoding")] InvalidPointEncoding,
    #[error("zero identifier")] ZeroIdentifier,
    #[error("duplicate identifier")] DuplicateIdentifier,
    #[error("invalid encoding: {0}")] InvalidEncoding(&'static str),
    #[error("share failed Feldman verification for dealer {0:?}")] InvalidShare(Identifier),
    #[error("threshold > participants")] InvalidThreshold,
    // Defined now, used in Phase 1:
    #[error("partial signature invalid; culprit {0:?}")] Culprit(Identifier),
    #[error("aggregate signature failed verification")] InvalidSignature,
}
```
No public API in any module `panic!`s, `unwrap()`s, or `expect()`s on caller- or peer-controlled input. Internal invariants may `debug_assert!`.

---

## 6. `keygen.rs` + `vss.rs` — Feldman VSS and trusted-dealer keygen

**`vss.rs` (pure functions, ported and corrected from the existing logic):**
```rust
/// Public commitments C_0..C_{t-1} = a_k·G for one dealer's degree-(t-1) polynomial.
pub struct Commitments(pub Vec<GElement>);

/// Feldman verification: share·G == Σ_k C_k · (id^k).
pub fn verify_share(id: Identifier, share: &SigningShare, commitments: &Commitments) -> Result<(), Error>;

/// Evaluate the public commitment polynomial at an identifier: yields X_i = s_i·G. (Amendment §2.)
pub fn verifying_share(id: Identifier, commitments: &Commitments) -> GElement;
```
Fix the legacy naming: the polynomial has `t` coefficients (degree `t-1`); reject `threshold > participants` and `threshold == 0` with `InvalidThreshold`.

**`keygen.rs` (trusted dealer; Pedersen DKG arrives in Phase 2 behind these same types):**
```rust
pub struct KeyPackage     { pub id: Identifier, pub signing_share: SigningShare, pub verifying_share: GElement }
pub struct PublicKeyPackage {
    pub group_public: GElement,                 // X = Σ dealers' C_0  (the aggregate Ed25519 public key)
    pub verifying_shares: BTreeMap<Identifier, GElement>, // X_i for every participant — feeds P1 identifiable abort
    pub threshold: u16,
}

/// Sample a degree-(t-1) polynomial with secret a_0, hand out shares to `ids`, zeroize the polynomial.
/// Returns one KeyPackage per id plus the PublicKeyPackage. Reconstruction is NOT part of this API.
pub fn trusted_dealer_keygen(threshold: u16, ids: &[Identifier], rng: &mut impl rand_core::CryptoRng)
    -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), Error>;
```
`validate_identifier_set(ids)` is called first. The secret polynomial is zeroized before return. **No secret share is ever placed in `PublicKeyPackage` or any wire type.**

---

## 7. Tests — the Phase 0 green gate

**`tests/reconstruction.rs`** (this is the gate; reconstruction lives only in tests):
- 2-of-3 and 3-of-5 trusted-dealer keygen.
- Lagrange-interpolate any `t` signing shares at `x=0`; assert the result `·G == group_public`.
- Assert any `t-1` shares interpolate to a value whose `·G != group_public` (the secret is not determined by `t-1` shares).
- Feldman `verify_share` passes for every honest share; a tampered share fails with `InvalidShare`.
- `verifying_share(id, commitments) == KeyPackage.verifying_share` for every id (the §2 derivation is correct — Phase 1 depends on this).

**`tests/identifiers.rs`** (amendment §5):
- `Identifier::try_from_u64(0)` → `Err(ZeroIdentifier)`; the zero 32-byte encoding → `Err(ZeroIdentifier)`.
- `validate_identifier_set` with a duplicate → `Err(DuplicateIdentifier)`.
- Non-canonical scalar bytes → `Err(NonCanonicalScalar)` (no silent reduction).
- A known small-order point encoding → `Err(NonPrimeOrderPoint)`.
- Redacting `Debug` on `SigningShare` contains no key bytes.

---

## 8. Phase 0 Definition of Done

1. Shell crates deleted; `nodeDb/.env` purged from git history; absolute `diesel.toml` path gone. `git log` shows the demolition commit.
2. Single `frost-core` library crate; `#![forbid(unsafe_code)]`; dependency allowlist (§2.3) respected — no `tokio`/`diesel`/`reqwest`/`solana-*`.
3. `group.rs` validates: non-canonical scalars rejected, non-prime-order points rejected, zero identifier rejected, duplicate-identifier set rejected — each proven in `tests/identifiers.rs`.
4. `secret.rs` types are `ZeroizeOnDrop`, non-`Debug`-derived (redacting `Debug` proven clean), non-`Serialize`; `SigningNonces` is single-use by type (no `Clone`/`Copy`).
5. `vss.rs` Feldman verify + `verifying_share` correct; threshold validation present.
6. `keygen.rs` trusted-dealer emits `KeyPackage`s and a `PublicKeyPackage` containing `group_public` and all `verifying_shares`; the secret polynomial is zeroized; no secret in any public/wire type.
7. `tests/reconstruction.rs` green at 2-of-3 and 3-of-5, including the `t-1`-reveals-nothing assertion and the `verifying_share` equality.
8. `cargo build`, `cargo clippy -D warnings`, `cargo test` all clean.
9. **Freeze recorded:** `group.rs`, `secret.rs`, `message.rs`, `vss.rs` are frozen; a line in `CLAUDE.md` says so.

No signing, no nonces-in-anger, no Solana, no networking this phase.

---

## Appendix A — `CLAUDE.md` (create this phase)

```markdown
## Authoritative specs
- docs/specs/kickoff-brief.md        — strategy, audit, architecture, DoD
- docs/specs/kickoff-amendment-1.md  — adversarial/crypto upgrades (binding)
- docs/specs/phase0-spec.md          — CURRENT: demolition, sans-IO core, group layer
- docs/specs/phase1-spec.md          — FROST signing + KAT/differential harness

## Hard rules
1. frost-core is sans-IO. No tokio/reqwest/diesel/Postgres/solana-* in the crypto path.
   #![forbid(unsafe_code)] crate-wide. group.rs/secret.rs/message.rs/vss.rs FREEZE after P0.
2. Reject, never coerce: non-canonical scalars, non-prime-order points, zero/duplicate
   identifiers -> Result::Err. Zero panic/unwrap/expect on caller- or peer-controlled input.
3. No secret on any non-work path: no Debug derive, no Serialize, no logs, no plaintext-at-rest.
   Zeroize all secret material. Nonces single-use by type.
4. keygen emits verifying shares X_i (public, from VSS commitments) — Phase 1 needs them.
5. Build only from facts: tests assert, specs cite. No marketing words, no emoji, no exclamation.

## Scope discipline
One session, one deliverable. End with cargo build + clippy -D warnings + test, list changes, STOP.
```

## Appendix B — Claude Code execution plan (Phase 0)

| # | Session | Deliverable | Done when |
|---|---|---|---|
| 0.1 | Demolition + scaffold | `git rm` shell crates; purge `.env` from history; workspace + `frost-core` skeleton; `#![forbid(unsafe_code)]`; `CLAUDE.md` (App. A) | `cargo build` clean; history clean; tree shown |
| 0.2 | Group + secret + error layer | `group.rs` (§3), `secret.rs` (§4), `error.rs` (§5); `tests/identifiers.rs` | identifier/canonical/subgroup rejections green; redacting `Debug` clean |
| 0.3 | VSS + keygen + gate | `vss.rs` + `keygen.rs` (§6); `tests/reconstruction.rs` (§7) | 2-of-3 + 3-of-5 reconstruct; `t-1` reveals nothing; **freeze recorded** |

**Session 0.1 prompt**
> Read `docs/specs/phase0-spec.md` §1–§2 and `kickoff-amendment-1.md`. Create `CLAUDE.md` (App. A). Execute **Session 0.1 only**: `git rm -r orchestrator node store nodeDb`; purge `nodeDb/.env` from git history (filter-repo or BFG) and report the clean `git log`; scaffold the `frost-ed25519-kit` workspace with one `frost-core` lib crate, `#![forbid(unsafe_code)]`, workspace lints, and the §2.3 dependency allowlist (nothing else). Show the tree and `frost-core/src/lib.rs`. Commit, run `cargo build`, STOP.

**Session 0.2 prompt**
> Read `phase0-spec.md` §3–§5 and `kickoff-amendment-1.md` §5. Execute **Session 0.2 only**: implement `group.rs` (validated CT scalar/point/identifier, reject non-canonical/non-prime-order/zero/duplicate), `secret.rs` (Zeroize-on-drop secret types, single-use `SigningNonces` by type, redacting `Debug`, no `Serialize`), and `error.rs`. Write `tests/identifiers.rs` proving every rejection and the clean `Debug`. Do not implement signing. Commit, run build + clippy -D warnings + test, list changes, STOP.

**Session 0.3 prompt**
> Read `phase0-spec.md` §6–§8. Execute **Session 0.3 only**: port and correct Feldman VSS into `vss.rs` (verify_share + verifying_share), implement `keygen.rs` trusted-dealer emitting `KeyPackage`s and a `PublicKeyPackage` with `group_public` and all `verifying_shares`, zeroizing the polynomial. Write `tests/reconstruction.rs` per §7 (2-of-3, 3-of-5, `t-1`-reveals-nothing, `verifying_share` equality). Record the freeze of group/secret/message/vss in `CLAUDE.md`. Commit, run build + clippy + test, list changes, STOP. Phase 0 complete.
