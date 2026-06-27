//! Zeroization & secret-hygiene structural audit (phase3-spec §6.2).
//!
//! # What this proves — and the honest limit it does not
//!
//! For every secret type in `frost-core`, this suite asserts the three hygiene
//! properties the design promises, **as far as the type system and `Debug` make
//! observable**:
//!
//! 1. **Zeroize-on-drop is wired.** The leaf secret types — [`SigningShare`],
//!    [`SigningNonces`], and the (crate-private) `SecretPolynomial` — carry
//!    `#[derive(Zeroize, ZeroizeOnDrop)]`; `assert_zeroize_on_drop` pins that at the
//!    trait level for the two that cross the public API. The DKG packages
//!    (`round1::SecretPackage`, `round2::SecretPackage`, `round2::Package`) are
//!    **not** `ZeroizeOnDrop` themselves — they hold their secret *only* inside a
//!    zeroizing leaf (`Zeroizing<Vec<Scalar>>` or a `SigningShare`), so dropping the
//!    package drops and wipes that leaf. That composition is what the
//!    redacting-`Debug` checks below exercise on real instances; it is a fact of the
//!    frozen `secret.rs`/`dkg.rs` source, not asserted as a trait bound it does not
//!    have.
//! 2. **`Debug` redacts.** Each secret type, formatted with `{:?}`, contains no key
//!    bytes — proven by formatting a real instance and asserting its actual secret
//!    bytes do not appear in the string.
//! 3. **No `Serialize` on secrets** (except `round2::Package`). `frost-core` does
//!    **not depend on `serde`** at all (the shipped graph is six crates;
//!    `deny.toml` bans the rest), so no type *can* implement `serde::Serialize` —
//!    the property is enforced by the supply-chain gate, not derivable here. The one
//!    principled exception is [`round2::Package`], whose hand-rolled `serialize`
//!    returns secret bytes wrapped in [`Zeroizing`] for a private, authenticated
//!    channel (phase2-spec §7; recorded in `ARCHITECTURE.md`); the audit confirms
//!    that method exists and returns a zeroizing buffer.
//!
//! **Honest limit (stated in `THREAT-MODEL.md`):** verifying that a *freed memory
//! page* is actually scrubbed requires inspecting freed memory, which needs
//! `unsafe` — and the crate is `#![forbid(unsafe_code)]`. This audit therefore
//! proves the **types and traits** are correct (zeroize-on-drop is wired, no secret
//! is `Debug`/`Serialize`-leaked), not that a specific physical page was zeroed.

use std::collections::BTreeMap;

use frost_core::dkg::{part1, part2, round1, round2};
use frost_core::group::Identifier;
use frost_core::secret::{SigningNonces, SigningShare};
use frost_core::sign::commit;
use frost_core::trusted_dealer_keygen;

use rand::SeedableRng;
use rand::rngs::StdRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compiles only if `T: ZeroizeOnDrop`. Used to pin the trait at the type level.
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
/// Compiles only if `T: Zeroize`.
fn assert_zeroize<T: Zeroize>() {}

/// Lowercase hex of `bytes`, the form a careless `Debug` would leak.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn id(x: u64) -> Identifier {
    Identifier::try_from_u64(x).unwrap()
}

/// `peers` map for participant `i`'s `part2`: every other participant's round-1
/// package (self excluded, per the DKG convention).
fn peers_of(
    all: &BTreeMap<Identifier, round1::Package>,
    me: Identifier,
) -> BTreeMap<Identifier, round1::Package> {
    all.iter()
        .filter(|&(&k, _)| k != me)
        .map(|(&k, v)| (k, v.clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Zeroize-on-drop is wired (trait level, for the public leaf secret types).
// ---------------------------------------------------------------------------

#[test]
fn leaf_secret_types_are_zeroize_on_drop() {
    // The two leaf secret types that cross the public API derive ZeroizeOnDrop.
    assert_zeroize_on_drop::<SigningShare>();
    assert_zeroize_on_drop::<SigningNonces>();
    assert_zeroize::<SigningShare>();
    assert_zeroize::<SigningNonces>();
    // `SecretPolynomial` also derives ZeroizeOnDrop (visible in secret.rs) but is
    // `pub(crate)` — it never crosses the API boundary, so it is not nameable here;
    // its derive is its guarantee at the point of definition. The DKG package
    // structs zeroize compositionally (their secret lives in a zeroizing leaf), a
    // property the redacting-Debug checks below exercise on real instances.
}

// ---------------------------------------------------------------------------
// 2. Debug redacts — no key bytes in the formatted string, on real instances.
// ---------------------------------------------------------------------------

#[test]
fn signing_share_debug_is_redacted() {
    let mut rng = StdRng::seed_from_u64(1);
    let (kps, _public) = trusted_dealer_keygen(2, &[id(1), id(2), id(3)], &mut rng).unwrap();
    let share = &kps[&id(1)].signing_share;

    let secret_bytes = share.to_scalar().to_bytes();
    let dbg = format!("{share:?}");
    assert!(!dbg.contains(&hex(&secret_bytes)), "Debug leaked the share bytes");
    assert!(dbg.contains("redacted"), "Debug should mark the share redacted");
}

#[test]
fn signing_nonces_debug_is_redacted() {
    let mut rng = StdRng::seed_from_u64(2);
    let (kps, _public) = trusted_dealer_keygen(2, &[id(1), id(2)], &mut rng).unwrap();
    let (nonces, _commitments) = commit(id(1), &kps[&id(1)].signing_share, &mut rng);

    // No public getter for the nonce scalars; the redacting Debug is a fixed,
    // byte-free string. Assert it exactly — the strongest available check.
    assert_eq!(format!("{nonces:?}"), "SigningNonces(<redacted>)");
}

#[test]
fn dkg_round1_secret_package_debug_is_redacted() {
    let mut rng = StdRng::seed_from_u64(3);
    let (secret1, _pkg1) = part1(id(1), 2, 3, &mut rng).unwrap();

    // The only secret field (the polynomial coefficients) is shown as the literal
    // "<redacted>"; the public identifier/threshold/max_signers are not secret.
    let dbg = format!("{secret1:?}");
    assert!(dbg.contains("<redacted>"), "round1::SecretPackage must redact coefficients");
}

#[test]
fn dkg_round2_secret_types_debug_is_redacted() {
    // Minimal honest 2-party DKG to reach the round-2 secret types.
    let mut rng = StdRng::seed_from_u64(4);
    let (s1_a, p1_a) = part1(id(1), 2, 2, &mut rng).unwrap();
    let (s1_b, p1_b) = part1(id(2), 2, 2, &mut rng).unwrap();
    let mut all = BTreeMap::new();
    all.insert(id(1), p1_a);
    all.insert(id(2), p1_b);

    let (secret2_a, outgoing_a) = part2(s1_a, &peers_of(&all, id(1))).unwrap();
    let _ = part2(s1_b, &peers_of(&all, id(2))).unwrap();

    // round2::SecretPackage — own_share shown as "<redacted>".
    assert!(
        format!("{secret2_a:?}").contains("<redacted>"),
        "round2::SecretPackage must redact own_share"
    );

    // round2::Package — the secret-in-transit share. Its serialized form exposes
    // the share bytes (last 32); assert those exact bytes never appear in Debug
    // (the share is redacted via SigningShare's Debug inside the derived one).
    let (_recipient, pkg) = outgoing_a.iter().next().expect("a round2 package was produced");
    let wire = pkg.serialize();
    let share_bytes = &wire[32..64];
    let dbg = format!("{pkg:?}");
    assert!(
        !dbg.contains(&hex(share_bytes)),
        "round2::Package Debug leaked the secret share bytes"
    );
    assert!(dbg.contains("<redacted>"), "round2::Package must redact its share");
}

// ---------------------------------------------------------------------------
// 3. The one Serialize exception — round2::Package — returns zeroizing bytes.
//    (All other secrets cannot implement serde::Serialize: frost-core has no
//    serde dependency, enforced by deny.toml. See the module doc-comment.)
// ---------------------------------------------------------------------------

#[test]
fn round2_package_serialize_returns_zeroizing_bytes() {
    let mut rng = StdRng::seed_from_u64(5);
    let (s1_a, p1_a) = part1(id(1), 2, 2, &mut rng).unwrap();
    let (_s1_b, p1_b) = part1(id(2), 2, 2, &mut rng).unwrap();
    let mut all = BTreeMap::new();
    all.insert(id(1), p1_a);
    all.insert(id(2), p1_b);

    let (_secret2, outgoing) = part2(s1_a, &peers_of(&all, id(1))).unwrap();
    let (_recipient, pkg) = outgoing.iter().next().unwrap();

    // The documented exception: a hand-rolled `serialize` (not serde) returning a
    // Zeroizing<Vec<u8>> of recipient_enc(32) ‖ share_enc(32) for a private channel.
    let wire: zeroize::Zeroizing<Vec<u8>> = pkg.serialize();
    assert_eq!(wire.len(), 64, "round2 wire is recipient(32) || share(32)");

    // Round-trips through the public deserializer (reject-never-coerce path).
    let back = round2::Package::deserialize(&wire).unwrap();
    assert_eq!(&back.serialize()[..], &wire[..], "round2::Package must round-trip");
}
