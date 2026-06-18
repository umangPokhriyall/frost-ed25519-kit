//! RFC 8032 aggregate verification and the per-partial check (phase1-spec §5).
//!
//! `verify` checks the cofactored RFC 8032 equation, so a FROST-produced
//! signature is a valid, interoperable Ed25519 signature (proven offline in the
//! Phase 4 `solana_compat` example, never broadcast). `verify_share` is the
//! per-partial check `aggregate` runs before summing; it is exposed for tests.
//!
//! Equations verified against `frost-core-2.2.0/src/verifying_key.rs:56-74`.

use curve25519_dalek::scalar::Scalar;

use crate::ciphersuite;
use crate::error::Error;
use crate::group::{GElement, GScalar, Identifier, validate_identifier_set};
use crate::keygen::PublicKeyPackage;
use crate::sign::{
    RhoPrefix, Signature, SignatureShare, SigningCommitments, compute_challenge,
    compute_group_commitment, lagrange_coefficient,
};

/// Standard Ed25519 verification of `(R, z)` under the group public key `A = public`.
///
/// Computes `c = H2(R_enc ‖ A_enc ‖ msg)` and checks the cofactored RFC 8032
/// equation `[8]·(z·G) == [8]·(R + c·A)` — equivalent to frost-core's
/// `h·(z·B − c·A − R) == identity` (`verifying_key.rs:61-69`, `h = 8`). All
/// `GElement`s here are torsion-free, so the cofactored and strict checks agree;
/// the cofactored form is the one off-the-shelf Ed25519 verifiers use.
pub fn verify(public: &GElement, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let r_enc = sig.r.to_compressed();
    let a_enc = public.to_compressed();
    let challenge = ciphersuite::h2(&[r_enc.as_slice(), a_enc.as_slice(), msg]);

    let eight = GScalar::from_scalar(Scalar::from(8u64));
    let lhs = GElement::generator().scalar_mul(&sig.z).scalar_mul(&eight);
    let rhs = (sig.r + public.scalar_mul(&challenge)).scalar_mul(&eight);
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// The per-partial verification check (phase1-spec §4.3 / amendment §2):
/// ```text
///   z_j·G  ==  (D_j + ρ_j·E_j)  +  (λ_j · c · X_j)
/// ```
/// where `X_j = public.verifying_shares[id_j]`. Returns `Err(Culprit(id_j))` if
/// the partial is bad, the signer has no commitment, or it has no verifying share
/// — naming the participant so the aggregator can act. `prefix` and `challenge`
/// are passed in so `aggregate` computes them once for the whole set.
pub(crate) fn verify_one_share(
    share: &SignatureShare,
    commitments: &[SigningCommitments],
    ids: &[Identifier],
    prefix: &RhoPrefix,
    challenge: &GScalar,
    public: &PublicKeyPackage,
) -> Result<(), Error> {
    let commitment = commitments
        .iter()
        .find(|c| c.id == share.id)
        .ok_or(Error::Culprit(share.id))?;
    let x_j = public
        .verifying_shares
        .get(&share.id)
        .ok_or(Error::Culprit(share.id))?;

    let rho_j = prefix.binding_factor(share.id);
    let lambda_j = lagrange_coefficient(share.id, ids)?;

    let lhs = GElement::generator().scalar_mul(&share.z);
    let rhs = commitment.hiding
        + commitment.binding.scalar_mul(&rho_j)
        + x_j.scalar_mul(&(lambda_j * *challenge));
    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::Culprit(share.id))
    }
}

/// Verify a single honest partial against its verifying share (phase1-spec §5).
/// Recomputes the binding factors, group commitment, and challenge over the
/// signer set, then runs the per-partial check. Returns `Err(Culprit(id))` on a
/// bad partial.
pub fn verify_share(
    share: &SignatureShare,
    commitments: &[SigningCommitments],
    public: &PublicKeyPackage,
    msg: &[u8],
) -> Result<(), Error> {
    let ids: Vec<Identifier> = commitments.iter().map(|c| c.id).collect();
    validate_identifier_set(&ids)?;
    let prefix = RhoPrefix::new(commitments, public, msg);
    let group_commitment = compute_group_commitment(commitments, &prefix);
    let challenge = compute_challenge(&group_commitment, public, msg);
    verify_one_share(share, commitments, &ids, &prefix, &challenge, public)
}
