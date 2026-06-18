//! Feldman VSS primitives (phase0-spec §6). FROZEN after P0.
//!
//! A dealer's degree-`(t-1)` secret polynomial `f` has public commitments
//! `C_k = a_k·G`. The commitment polynomial evaluated in the exponent at an
//! identifier yields that participant's verifying share `X_i = f(i)·G = s_i·G`,
//! and a share is valid exactly when `s_i·G` equals that evaluation.

use crate::error::Error;
use crate::group::{GElement, Identifier};
use crate::secret::SigningShare;

/// Public commitments `C_0..C_{t-1} = a_k·G` for one dealer's degree-`(t-1)`
/// polynomial. The polynomial has `t` coefficients (degree `t-1`).
pub struct Commitments(pub Vec<GElement>);

/// Evaluate the public commitment polynomial at an identifier in the exponent:
/// `Σ_k C_k · id^k = s_i·G = X_i` (phase0-spec §6 / amendment §2). Computed by
/// Horner's method; an empty commitment list yields the identity.
pub fn verifying_share(id: Identifier, commitments: &Commitments) -> GElement {
    let x = id.as_scalar();
    let mut acc = GElement::identity();
    for c in commitments.0.iter().rev() {
        acc = acc.scalar_mul(&x) + *c;
    }
    acc
}

/// Feldman verification: a share is valid iff `share·G == Σ_k C_k · id^k`.
/// On mismatch returns `Err(InvalidShare(id))` — naming the dealer/identifier.
pub fn verify_share(
    id: Identifier,
    share: &SigningShare,
    commitments: &Commitments,
) -> Result<(), Error> {
    let lhs = GElement::generator().scalar_mul(&share.to_scalar());
    let rhs = verifying_share(id, commitments);
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::InvalidShare(id))
    }
}
