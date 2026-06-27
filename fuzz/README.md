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
The committed budget is what was **actually run**, reported as exec count:

- **Stable bounded harness** (`tests/bounded.rs`, this environment, no libFuzzer):
  **3,600,036 execs across 6 targets, 0 crashes.**
  Per target: 6 fixed edge seeds + 3 input widths × 200,000 seeded-PRNG draws =
  600,006 execs. Reproduce:
  ```sh
  cargo test --manifest-path fuzz/Cargo.toml --test bounded -- --nocapture
  ```
- **Coverage-guided libFuzzer**: not run in this environment (no nightly /
  cargo-fuzz). Run locally with the commands above; record `N execs, 0 crashes`
  here when done. This is the exhaustive version; the bounded harness is the
  committed floor.

The seed corpus (`corpus/<target>/`) includes the boundary encodings: the zero
scalar/identifier, the group order `L` (smallest non-canonical scalar), an order-8
(non-prime-order) point, the Ed25519 basepoint and identity, and a valid round-2
package.
