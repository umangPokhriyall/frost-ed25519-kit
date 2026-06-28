# frost-core-fuzz — deserializer fuzzing (phase3-spec §5)

One fuzz target per public byte-deserializer in `frost-core`. The invariant for
every target (`src/lib.rs`):

> Arbitrary input either returns `Err`, or returns `Ok(value)` that **re-serializes
> to the same canonical bytes** — and **never panics, never accepts a non-canonical
> encoding, never accepts a non-prime-order point.**

An accepted non-canonical encoding re-serializes to *different* bytes and trips the
round-trip assertion; a non-prime-order point is rejected by the frozen group layer
and never reaches the `Ok` arm; a panic is a libFuzzer crash.

## Targets

| target | deserializer | input |
|---|---|---|
| `gscalar_from_canonical_bytes`        | `group::GScalar::from_canonical_bytes`     | 32 bytes |
| `gelement_from_compressed`            | `group::GElement::from_compressed`         | 32 bytes |
| `identifier_from_canonical_bytes`     | `group::Identifier::from_canonical_bytes`  | 32 bytes |
| `signing_share_from_canonical_bytes`  | `secret::SigningShare::from_canonical_bytes` | 32 bytes |
| `signature_from_bytes`                | `sign::Signature::from_bytes`              | 64 bytes |
| `round2_package_deserialize`          | `dkg::round2::Package::deserialize`        | 64 bytes |

### Why six and not eight

phase3-spec §5 also lists `SigningCommitments`, `SignatureShare`, and
`round1::Package`. In the **frozen** API these are structured value types with
public *fields* but **no byte-level `from_bytes`/`deserialize`** — `message.rs`
(the wire-type module) was never introduced (see `CLAUDE.md` freeze record), so
there is no deserializer entry point to fuzz for them. Their wire-relevant
components are exactly the inputs the six targets above exercise:

- `SigningCommitments` = an `Identifier` + two compressed `GElement`s →
  `identifier_from_canonical_bytes` + `gelement_from_compressed`.
- `SignatureShare` = an `Identifier` + a canonical `GScalar` →
  `identifier_from_canonical_bytes` + `gscalar_from_canonical_bytes`.
- `round1::Package` = a list of compressed `GElement`s + a Schnorr PoK (two
  `GElement`/`GScalar`s) → `gelement_from_compressed` + `gscalar_from_canonical_bytes`.

So the deserializer attack surface is fully covered; adding hand-rolled byte
parsers for the field structs would mean *adding logic to a frozen module*, which
Phase 3 forbids. `SigningShare::from_canonical_bytes` is fuzzed directly (it is a
real public deserializer the spec list folded into "SignatureShare").

## Toolchain and how to run

`cargo-fuzz` needs a **nightly** toolchain and the `cargo-fuzz` subcommand
(libFuzzer + the address sanitizer are linked into each target binary). It is
**not** installed in the default dev environment here; the fuzz targets are built
behind the `libfuzzer` feature so the stable workspace never links them:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run --features libfuzzer gscalar_from_canonical_bytes
# …one per target. Seed corpora live in corpus/<target>/.
```

## Workspace-gate exclusion

This crate is its **own** workspace (`[workspace]` in `Cargo.toml`) and is
`exclude`d from the root `frost-ed25519-kit` workspace, so it is **outside** the
`cargo build` / `cargo clippy --all-targets -D warnings` / `cargo test` gate
(phase3-spec §5, DoD §11). The shipped build stays stable and free of any nightly
requirement. `cargo tree -e normal -p frost-core` is unchanged by this crate.

## Committed budget — measured, not "clean"

Absence of a crash within a budget is not proof of total absence (phase3-spec §5).
The committed budget is what was **actually run**, reported as exec count.

### What the coverage-guided run found (and the bounded floor missed)

The Phase 4 coverage-guided libFuzzer run (below) found a real defect within
seconds that the bounded floor's random draws never hit: `GElement::from_compressed`
accepted **non-canonical point encodings** — a y-coordinate `>= the field prime`
(e.g. `EE FF..FF`, which is `y = p + 1`), and a set sign bit on the `x = 0` point
(`01 00..00 80`). dalek's `decompress()` silently canonicalizes these, so two
distinct byte strings denoted the same point — a malleability vector and a
"reject, never coerce" violation. Two targets crashed on it:
`gelement_from_compressed` and `signature_from_bytes` (the latter parses `R`
through `from_compressed`).

The bounded floor missed it because there are only ~19 non-canonical `y` values out
of `2^255`; uniform random 32-byte draws essentially never land on one. A
coverage-guided fuzzer, steered by the decode/torsion branches, reaches them fast.
This is exactly the strengthening phase3/§3.3 reserved the real run for.

**Fix** (authorized post-freeze exception, recorded in `CLAUDE.md`): `group.rs`
`from_compressed` now applies RFC 8032 strict decoding — re-encode the decompressed
point and reject if it differs from the input, before the torsion check.
Regression-pinned in `frost-core/tests/adversarial.rs`. After the fix all six
targets are crash-free (numbers below).

### Coverage-guided libFuzzer — the real run (Phase 4, post-fix)

Toolchain: `cargo 1.98.0-nightly` + `cargo-fuzz 0.13.2`, libFuzzer + AddressSanitizer,
`-max_total_time=60` per target. **104,624,899 execs across 6 targets, 0 crashes.**

| target | execs | wall-time | crashes |
|---|---|---|---|
| `gscalar_from_canonical_bytes`       | 25,104,249 | 61 s | 0 |
| `gelement_from_compressed`           |  1,936,018 | 61 s | 0 |
| `identifier_from_canonical_bytes`    | 21,047,225 | 61 s | 0 |
| `signing_share_from_canonical_bytes` | 22,781,943 | 61 s | 0 |
| `signature_from_bytes`               |  2,065,545 | 61 s | 0 |
| `round2_package_deserialize`         | 31,689,919 | 61 s | 0 |

The two point-parsing targets execute far fewer iterations per second: each
decompress + strict re-encode + torsion check is a full curve operation, and the
fuzzer explores far more states there (`cov: 298`/`363` vs `~160` for the scalar
targets). 60 s is the committed per-target budget; absence of a crash within it is
not proof of total absence (phase3-spec §5). Reproduce:
```sh
cargo +nightly fuzz run --features libfuzzer <target> -- -max_total_time=60
```

### Stable bounded harness — the CI-runnable floor

- **`tests/bounded.rs`** (this environment, no libFuzzer): **3,600,036 execs across
  6 targets, 0 crashes.** Per target: 6 fixed edge seeds + 3 input widths ×
  200,000 seeded-PRNG draws = 600,006 execs. Reproduce:
  ```sh
  cargo test --manifest-path fuzz/Cargo.toml --test bounded -- --nocapture
  ```
  This is the stable floor that runs without nightly; the coverage-guided run above
  is the exhaustive version.

The seed corpus (`corpus/<target>/`) includes the boundary encodings: the zero
scalar/identifier, the group order `L` (smallest non-canonical scalar), an order-8
(non-prime-order) point, the Ed25519 basepoint and identity, a valid round-2
package, and — added in Phase 4 — the two non-canonical point encodings the
coverage-guided run found (`seed-noncanonical-y-p-plus-1`,
`seed-noncanonical-r-sign-bit`), so the regression seed is committed, not only
discovered. The behavioural regression guard is `frost-core/tests/adversarial.rs`.
