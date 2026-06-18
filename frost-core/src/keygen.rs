//! Trusted-dealer key generation (phase0-spec §6).
//!
//! Stable but not frozen: Phase 2 replaces the trusted-dealer body with Pedersen
//! DKG behind these same `KeyPackage` / `PublicKeyPackage` types. The dealer
//! samples one degree-`(t-1)` polynomial, hands out one signing share per
//! identifier, and publishes the verifying shares `X_i = s_i·G` (derived from
//! the VSS commitments — no new secret material) so Phase 1 has them without a
//! keygen change. The secret polynomial is zeroized before return, and no secret
//! share is ever placed in `PublicKeyPackage`.

use std::collections::BTreeMap;

use crate::error::Error;
use crate::group::{Identifier, GElement, validate_identifier_set};
use crate::secret::{SecretPolynomial, SigningShare};
use crate::vss::{Commitments, verifying_share};

/// One participant's private output: its identifier, its secret signing share,
/// and its public verifying share `X_i = s_i·G`.
pub struct KeyPackage {
    pub id: Identifier,
    pub signing_share: SigningShare,
    pub verifying_share: GElement,
}

/// The public output, broadcast to all participants. Carries the aggregate
/// Ed25519 group key and every participant's verifying share (the latter feeds
/// Phase 1 identifiable abort). Contains no secret material.
pub struct PublicKeyPackage {
    /// `X = Σ dealers' C_0` — for the trusted dealer, `C_0 = a_0·G`.
    pub group_public: GElement,
    /// `X_i` for every participant.
    pub verifying_shares: BTreeMap<Identifier, GElement>,
    pub threshold: u16,
}

/// Sample a degree-`(t-1)` polynomial with secret `a_0`, hand out one share per
/// id, and return one `KeyPackage` per id plus the `PublicKeyPackage`. Rejects
/// `threshold == 0` and `threshold > participants` with `InvalidThreshold`, and
/// a zero/duplicate identifier set via `validate_identifier_set`. Reconstruction
/// is intentionally NOT part of this API.
pub fn trusted_dealer_keygen(
    threshold: u16,
    ids: &[Identifier],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), Error> {
    validate_identifier_set(ids)?;
    if threshold == 0 || threshold as usize > ids.len() {
        return Err(Error::InvalidThreshold);
    }

    let t = threshold as usize;
    let polynomial = SecretPolynomial::sample(t, rng);
    let commitments = Commitments(polynomial.commit());
    // C_0 = a_0·G is the aggregate group key. t >= 1 guarantees a constant term.
    let group_public = commitments.0[0];

    let mut key_packages = BTreeMap::new();
    let mut verifying_shares = BTreeMap::new();
    for &id in ids {
        let signing_share = SigningShare::from_scalar(polynomial.evaluate(id));
        // X_i = s_i·G, derived from public commitments (no new secret material).
        let verifying = verifying_share(id, &commitments);
        verifying_shares.insert(id, verifying);
        key_packages.insert(
            id,
            KeyPackage {
                id,
                signing_share,
                verifying_share: verifying,
            },
        );
    }

    // Zeroize the secret polynomial before returning (ZeroizeOnDrop).
    drop(polynomial);

    let public = PublicKeyPackage {
        group_public,
        verifying_shares,
        threshold,
    };
    Ok((key_packages, public))
}
