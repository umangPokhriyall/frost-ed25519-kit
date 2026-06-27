//! Deserializer invariant checks, shared by the libFuzzer targets
//! (`fuzz_targets/*.rs`) and the stable bounded harness (`tests/bounded.rs`).
//!
//! # The invariant every `check_*` enforces (phase3-spec §5)
//!
//! For each public byte-deserializer, arbitrary input must either
//! - return `Err`, or
//! - return `Ok(value)` whose re-serialization is **byte-for-byte the input**
//!   (round-trip / canonical stability),
//!
//! and **never panic, never accept a non-canonical encoding, never accept a
//! non-prime-order point.** Each check asserts the round-trip on the `Ok` arm; an
//! accepted non-canonical encoding would re-serialize to *different* bytes and trip
//! the assertion, and a non-prime-order point is rejected by the group layer so it
//! never reaches the `Ok` arm at all. A panic is a libFuzzer crash.
//!
//! These cover the real byte-deserializers in the frozen API. `SigningCommitments`,
//! `SignatureShare`, and `round1::Package` are structured value types with public
//! *fields* but no byte-level `from_bytes`/`deserialize` (`message.rs` was never
//! introduced); their wire-relevant components — compressed points and canonical
//! scalars/identifiers — are exactly the inputs the targets below exercise. See
//! `README.md`.

#![forbid(unsafe_code)]

use frost_core::dkg::round2;
use frost_core::group::{GElement, GScalar, Identifier};
use frost_core::secret::SigningShare;
use frost_core::sign::Signature;

/// `GScalar::from_canonical_bytes` — accept only canonical scalars in `[0, L)`.
pub fn check_gscalar(data: &[u8]) {
    let Some(b) = take32(data) else { return };
    if let Ok(s) = GScalar::from_canonical_bytes(b) {
        assert_eq!(s.to_bytes(), b, "GScalar accepted a non-canonical encoding");
    }
}

/// `GElement::from_compressed` — accept only canonical, torsion-free points.
pub fn check_gelement(data: &[u8]) {
    let Some(b) = take32(data) else { return };
    if let Ok(p) = GElement::from_compressed(b) {
        assert_eq!(
            p.to_compressed(),
            b,
            "GElement accepted a non-canonical point encoding"
        );
    }
}

/// `Identifier::from_canonical_bytes` — accept only nonzero canonical scalars.
pub fn check_identifier(data: &[u8]) {
    let Some(b) = take32(data) else { return };
    if let Ok(id) = Identifier::from_canonical_bytes(b) {
        assert_eq!(
            id.as_scalar().to_bytes(),
            b,
            "Identifier accepted a non-canonical encoding"
        );
        assert_ne!(b, [0u8; 32], "Identifier accepted the zero identifier");
    }
}

/// `SigningShare::from_canonical_bytes` — accept only canonical scalars.
pub fn check_signing_share(data: &[u8]) {
    let Some(b) = take32(data) else { return };
    if let Ok(s) = SigningShare::from_canonical_bytes(b) {
        assert_eq!(
            s.to_scalar().to_bytes(),
            b,
            "SigningShare accepted a non-canonical encoding"
        );
    }
}

/// `Signature::from_bytes` — 64-byte `R_enc(32) ‖ z_enc(32)`, `R` torsion-free,
/// `z` canonical.
pub fn check_signature(data: &[u8]) {
    if data.len() < 64 {
        return;
    }
    let mut b = [0u8; 64];
    b.copy_from_slice(&data[..64]);
    if let Ok(sig) = Signature::from_bytes(b) {
        assert_eq!(sig.to_bytes(), b, "Signature accepted a non-canonical encoding");
    }
}

/// `round2::Package::deserialize` — 64-byte `recipient_enc(32) ‖ share_enc(32)`,
/// nonzero canonical recipient, canonical share.
pub fn check_round2_package(data: &[u8]) {
    if let Ok(pkg) = round2::Package::deserialize(data) {
        assert_eq!(
            &pkg.serialize()[..],
            data,
            "round2::Package accepted a non-canonical encoding"
        );
    }
}

/// The first 32 bytes of `data`, or `None` if it is shorter. Deserializers that
/// take a fixed `[u8; 32]` are only exercised when enough bytes are present.
fn take32(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 32 {
        return None;
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[..32]);
    Some(b)
}
