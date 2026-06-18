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
use crate::group::{GElement, GScalar, Identifier};

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

    /// The share value as a validated scalar. The legitimate holder reads its
    /// own share to sign (Phase 1) or, in tests, to Lagrange-interpolate; the
    /// stored copy is still zeroized on drop.
    pub fn to_scalar(&self) -> GScalar {
        GScalar::from_scalar(self.0)
    }

    /// Wrap a scalar produced by keygen polynomial evaluation. Crate-internal.
    pub(crate) fn from_scalar(s: GScalar) -> Self {
        SigningShare(s.as_scalar())
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

// Phase 1 fills the hedged constructor and the consuming reader that the Phase 0
// doc-comment above forecast ("the into_partial(self, ..) consumer land in Phase
// 1"). Both are `pub(crate)`: the FROZEN public contract — no Clone/Copy, no
// Serialize, no non-redacting Debug, ZeroizeOnDrop, consumed by value — is
// unchanged. The single-use container is the same; only its crate-internal body
// is filled (phase1-spec §1.1/§2; sign.rs is the only caller).
impl SigningNonces {
    /// Build the single-use pair from the hedged nonce scalars `d_i`, `e_i`
    /// derived in `sign::commit` (`H3(random ‖ encode(share))`).
    pub(crate) fn from_scalars(hiding: GScalar, binding: GScalar) -> Self {
        SigningNonces {
            hiding: hiding.as_scalar(),
            binding: binding.as_scalar(),
        }
    }

    /// Consume the pair, returning `(d_i, e_i)` for the round-2 partial. The
    /// stored copies are zeroized when `self` is dropped at the end of this call,
    /// so the container cannot be reused — single use enforced by value.
    pub(crate) fn into_scalars(self) -> (GScalar, GScalar) {
        (
            GScalar::from_scalar(self.hiding),
            GScalar::from_scalar(self.binding),
        )
    }
}

/// A degree-`(t-1)` secret polynomial `a_0 + a_1·x + … + a_{t-1}·x^{t-1}` used
/// by trusted-dealer keygen. The constant term `a_0` is the group secret. The
/// coefficients are zeroized on drop, after shares are derived.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretPolynomial {
    coeffs: Vec<Scalar>,
}

impl SecretPolynomial {
    /// Sample a polynomial with `t` random coefficients (degree `t-1`). Caller
    /// guarantees `t >= 1`.
    pub(crate) fn sample(t: usize, rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng)) -> Self {
        let coeffs = (0..t).map(|_| Scalar::random(rng)).collect();
        SecretPolynomial { coeffs }
    }

    /// Evaluate the polynomial at an identifier (Horner), yielding the signing
    /// share `s_i = f(id)`.
    pub(crate) fn evaluate(&self, id: Identifier) -> GScalar {
        let x = id.as_scalar().as_scalar();
        let mut acc = Scalar::ZERO;
        for c in self.coeffs.iter().rev() {
            acc = acc * x + *c;
        }
        GScalar::from_scalar(acc)
    }

    /// The public Feldman commitments `C_k = a_k·G`. Returns only public points;
    /// the secret coefficients never leave this type.
    pub(crate) fn commit(&self) -> Vec<GElement> {
        let g = GElement::generator();
        self.coeffs
            .iter()
            .map(|c| g.scalar_mul(&GScalar::from_scalar(*c)))
            .collect()
    }
}
