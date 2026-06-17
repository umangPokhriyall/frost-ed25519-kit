//! Secret-hygiene types (phase0-spec §4). FROZEN after P0.
//!
//! Hard rules for every type here:
//! - `ZeroizeOnDrop`: secret material is wiped when the value is dropped.
//! - No `Debug` derive — a hand-written `Debug` redacts the contents.
//! - No `Serialize`: secrets never become a wire type (the crate does not even
//!   depend on `serde`).
//! - No `Clone`/`Copy` unless unavoidable, so duplication is deliberate.

use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;
use crate::group::GScalar;

/// A signing share `s_i`. Zeroized on drop. No `Debug` derive, no `Serialize`,
/// no `Clone`/`Copy`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningShare(Scalar);

impl SigningShare {
    /// Import a signing share from its canonical scalar encoding. Rejects
    /// non-canonical bytes (`NonCanonicalScalar`) — never reduces mod L.
    pub fn from_canonical_bytes(b: [u8; 32]) -> Result<Self, Error> {
        let scalar = GScalar::from_canonical_bytes(b)?;
        Ok(SigningShare(scalar.as_scalar()))
    }
}

// Redacting Debug: never prints key bytes (proven by tests/identifiers.rs).
impl core::fmt::Debug for SigningShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningShare(<redacted>)")
    }
}

/// A single-use nonce pair (hiding `d_i`, binding `e_i`). Zeroized on drop.
///
/// Single use is enforced by the type system, not a runtime check: there is no
/// `Clone` and no `Copy`, and the consumer takes `self` by value. The hedged
/// RFC 9591 derivation `H3(random ‖ secret)` and the `into_partial(self, ..)`
/// consumer land in Phase 1 (kickoff-amendment-1 §3); this is the single-use
/// container the type system locks in now (phase0-spec §4).
#[derive(Zeroize, ZeroizeOnDrop)]
// The fields are read by the `into_partial(self, ..)` consumer added in Phase 1;
// the container and its single-use property are what Phase 0 freezes.
#[allow(dead_code)]
pub struct SigningNonces {
    hiding: Scalar,
    binding: Scalar,
}

// Redacting Debug: never prints nonce bytes.
impl core::fmt::Debug for SigningNonces {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningNonces(<redacted>)")
    }
}
