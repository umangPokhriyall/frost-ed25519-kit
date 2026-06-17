//! Identifier-discipline and secret-hygiene rejections (phase0-spec §7,
//! kickoff-amendment-1 §5). Each test proves a "reject, never coerce" rule.

use frost_core::error::Error;
use frost_core::group::{GElement, GScalar, Identifier, validate_identifier_set};
use frost_core::secret::SigningShare;

/// The zero identifier `x = 0` is the secret's own coordinate; reject it.
#[test]
fn zero_identifier_from_u64_is_rejected() {
    assert!(matches!(
        Identifier::try_from_u64(0),
        Err(Error::ZeroIdentifier)
    ));
}

/// The canonical zero encoding (32 zero bytes) is a valid scalar but an invalid
/// identifier — rejected as `ZeroIdentifier`, not `NonCanonicalScalar`.
#[test]
fn zero_identifier_from_bytes_is_rejected() {
    let zero = [0u8; 32];
    assert!(matches!(
        Identifier::from_canonical_bytes(zero),
        Err(Error::ZeroIdentifier)
    ));
    // ...while it is a perfectly canonical *scalar*:
    assert!(GScalar::from_canonical_bytes(zero).is_ok());
}

/// Duplicate identifiers make a Lagrange denominator `(x_i − x_j) = 0`; reject.
#[test]
fn duplicate_identifier_set_is_rejected() {
    let a = Identifier::try_from_u64(1).expect("1 is nonzero");
    let b = Identifier::try_from_u64(2).expect("2 is nonzero");

    assert!(matches!(
        validate_identifier_set(&[a, b, a]),
        Err(Error::DuplicateIdentifier)
    ));
    // A set with no duplicates passes.
    assert!(validate_identifier_set(&[a, b]).is_ok());
}

/// Non-canonical scalar bytes (here all-`0xff`, far above the group order L)
/// are rejected, never silently reduced mod L.
#[test]
fn non_canonical_scalar_is_rejected() {
    let non_canonical = [0xffu8; 32];
    assert!(matches!(
        GScalar::from_canonical_bytes(non_canonical),
        Err(Error::NonCanonicalScalar)
    ));
}

/// A known order-8 point (from the edwards25519 small-order set) decompresses
/// but is not torsion-free; reject it as `NonPrimeOrderPoint` (cofactor guard).
#[test]
fn small_order_point_is_rejected() {
    let encoded = hex::decode("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
        .expect("valid hex");
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&encoded);
    assert!(matches!(
        GElement::from_compressed(bytes),
        Err(Error::NonPrimeOrderPoint)
    ));
    // Sanity: a torsion-free point (the generator) is accepted.
    let generator = GElement::generator().to_compressed();
    assert!(GElement::from_compressed(generator).is_ok());
}

/// The redacting `Debug` on `SigningShare` leaks no key bytes.
#[test]
fn signing_share_debug_is_redacted() {
    // A known canonical secret: the scalar 7 (little-endian).
    let mut secret = [0u8; 32];
    secret[0] = 7;
    let share = SigningShare::from_canonical_bytes(secret).expect("7 is canonical");

    let rendered = format!("{share:?}");
    assert_eq!(rendered, "SigningShare(<redacted>)");
    // The secret's hex never appears in the rendered Debug.
    assert!(!rendered.contains(&hex::encode(secret)));
}
