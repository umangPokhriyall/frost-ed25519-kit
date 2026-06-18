//! FROST(Ed25519, SHA-512) two-round signing (phase1-spec §4), hand-rolled on the
//! frozen `frost-core` group/secret layer. `frost-ed25519` is the differential
//! oracle in tests, never a dependency of this code path.
//!
//! This session (1.1) implements round 1 `commit` (hedged, single-use) and round 2
//! `sign` (binding factors → group commitment → challenge → Lagrange → partial).
//! `aggregate` with identifiable abort and RFC 8032 `verify` land in Session 1.2.
//!
//! Every encoding here was verified against RFC 9591 and `frost-ed25519` v2.2.0;
//! see `ciphersuite.rs` for the provenance of each hash, and the per-step notes
//! below for the round-2 arithmetic.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::ciphersuite;
use crate::error::Error;
use crate::group::{GElement, GScalar, Identifier, validate_identifier_set};
use crate::keygen::PublicKeyPackage;
use crate::secret::{SigningNonces, SigningShare};

/// The public per-signer round-1 output: identifier plus the hiding/binding
/// commitments `D_i = d_i·G`, `E_i = e_i·G`. Carries no secret material
/// (phase1-spec §6), so it is a plain transport-agnostic value type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningCommitments {
    pub id: Identifier,
    /// `D_i = d_i·G` (hiding).
    pub hiding: GElement,
    /// `E_i = e_i·G` (binding).
    pub binding: GElement,
}

/// One signer's round-2 output: identifier and the partial signature scalar `z_i`.
/// Public (the aggregator verifies it against `X_i`); no secret material.
// No `Debug`: `GScalar` deliberately does not implement `Debug` (group.rs).
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureShare {
    pub id: Identifier,
    pub z: GScalar,
}

/// The aggregated FROST signature `(R, z)`. It is a standard Ed25519 signature:
/// it serializes to 64 bytes `R_enc(32) ‖ z_enc(32)` and verifies under the RFC
/// 8032 equation (`verify`), so an off-the-shelf Ed25519 verifier accepts it.
/// Public value type, no secret material (phase1-spec §6).
// No `Debug`: `GScalar` deliberately does not implement `Debug` (group.rs).
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// `R` — the group commitment (`R_enc` is the first 32 bytes).
    pub r: GElement,
    /// `z` — the aggregated response scalar (`z_enc` is the last 32 bytes).
    pub z: GScalar,
}

impl Signature {
    /// The 64-byte Ed25519 wire encoding `R_enc(32) ‖ z_enc(32)`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r.to_compressed());
        out[32..].copy_from_slice(&self.z.to_bytes());
        out
    }

    /// Decode a 64-byte signature, validating `R` (prime-order point) and `z`
    /// (canonical scalar). Rejects, never coerces (`group.rs` hard rule).
    pub fn from_bytes(b: [u8; 64]) -> Result<Self, Error> {
        let mut r_enc = [0u8; 32];
        r_enc.copy_from_slice(&b[..32]);
        let mut z_enc = [0u8; 32];
        z_enc.copy_from_slice(&b[32..]);
        let r = GElement::from_compressed(r_enc)?;
        let z = GScalar::from_canonical_bytes(z_enc)?;
        Ok(Signature { r, z })
    }
}

/// Round 1 — generate a single-use nonce pair, **hedged** against RNG failure
/// (amendment §3 / RFC 9591 §5.1):
/// ```text
///   d_i = H3(random_bytes(32) ‖ encode(signing_share))
///   e_i = H3(random_bytes(32) ‖ encode(signing_share))   // independent random
/// ```
/// Mixing the share entropy means a fully predictable RNG still cannot cause
/// nonce reuse. Returns the secret [`SigningNonces`] (kept by the signer, single-use
/// by type) and the public [`SigningCommitments`] `(D_i, E_i)`.
///
/// `id` populates the returned `SigningCommitments.id`; the signer supplies its own
/// identifier from its `KeyPackage` (the RFC's `commit` derives only the secret,
/// leaving the coordinator to attach the identifier — here it is attached up front).
pub fn commit(
    id: Identifier,
    signing_share: &SigningShare,
    rng: &mut (impl RngCore + CryptoRng),
) -> (SigningNonces, SigningCommitments) {
    // encode(share): the canonical 32-byte little-endian scalar. A work-path read
    // of the signer's own secret; the copy is zeroized below.
    let mut share_enc = signing_share.to_scalar().to_bytes();
    let mut rand_d = [0u8; 32];
    let mut rand_e = [0u8; 32];
    rng.fill_bytes(&mut rand_d);
    rng.fill_bytes(&mut rand_e);

    let d = ciphersuite::h3(&[rand_d.as_slice(), share_enc.as_slice()]);
    let e = ciphersuite::h3(&[rand_e.as_slice(), share_enc.as_slice()]);

    let g = GElement::generator();
    let hiding = g.scalar_mul(&d);
    let binding = g.scalar_mul(&e);

    // d, e move into the single-use container (ZeroizeOnDrop).
    let nonces = SigningNonces::from_scalars(d, e);
    let commitments = SigningCommitments { id, hiding, binding };

    share_enc.zeroize();
    rand_d.zeroize();
    rand_e.zeroize();

    (nonces, commitments)
}

/// Round 2 — produce this signer's partial signature `z_i` over `msg`.
///
/// `commitments` is the full chosen signer set `(id, D_j, E_j)`, used to derive
/// the per-signer binding factors. `nonces` is consumed by value: single use is
/// enforced by the type, and the nonce pair is zeroized when this call returns.
///
/// Steps (phase1-spec §4.2), each verified against `frost-ed25519` v2.2.0:
/// 1. validate the signer set; require `|set| >= threshold`.
/// 2. `msg_hash = H4(msg)`, `com_hash = H5(encode_commitment_list)`.
/// 3. `ρ_j = H1(group_public_enc ‖ msg_hash ‖ com_hash ‖ id_enc(j))`.
/// 4. `R = Σ_j (D_j + ρ_j·E_j)`.
/// 5. `c = H2(R_enc ‖ group_public_enc ‖ msg)`.
/// 6. `λ_i` for `my_id` over the signer set.
/// 7. `z_i = d_i + (ρ_i·e_i) + (λ_i·c·s_i)`.
pub fn sign(
    signing_share: &SigningShare,
    nonces: SigningNonces,
    my_id: Identifier,
    commitments: &[SigningCommitments],
    public: &PublicKeyPackage,
    msg: &[u8],
) -> Result<SignatureShare, Error> {
    // 1. Validate the signer set (rejects duplicates) and the threshold.
    let ids: Vec<Identifier> = commitments.iter().map(|c| c.id).collect();
    validate_identifier_set(&ids)?;
    if ids.len() < public.threshold as usize {
        return Err(Error::InvalidThreshold);
    }

    // 2-3. Per-signer binding factors (rho prefix + H1) — shared encoding.
    let prefix = RhoPrefix::new(commitments, public, msg);
    // 4. Group commitment R = Σ_j (D_j + ρ_j·E_j).
    let group_commitment = compute_group_commitment(commitments, &prefix);
    // 5. Challenge c = H2(R_enc ‖ group_public_enc ‖ msg).
    let challenge = compute_challenge(&group_commitment, public, msg);
    // 6. Lagrange coefficient λ_i for my_id over the signer set (Err if absent).
    let lambda = lagrange_coefficient(my_id, &ids)?;

    // 7. z_i = d_i + (ρ_i·e_i) + (λ_i·c·s_i). `nonces` consumed here, then dropped
    //    (zeroized). d_i/e_i live transiently on this work-path stack.
    let rho_i = prefix.binding_factor(my_id);
    let (d_i, e_i) = nonces.into_scalars();
    let s_i = signing_share.to_scalar();
    let z = d_i + (rho_i * e_i) + (lambda * challenge * s_i);

    Ok(SignatureShare { id: my_id, z })
}

/// Aggregate the partial signatures into one Ed25519 signature, with
/// **identifiable abort** (amendment §2 / phase1-spec §4.3).
///
/// Recomputes `R`, the binding factors `ρ_j`, the challenge `c`, and each `λ_j`,
/// then — **before summing** — verifies every partial against its public verifying
/// share `X_j`:
/// ```text
///   z_j·G  ==  (D_j + ρ_j·E_j)  +  (λ_j · c · X_j)
/// ```
/// On the first failure it returns `Err(Culprit(id_j))`, naming the participant.
/// Only when all partials verify does it sum `z = Σ z_j` and return
/// `Signature { r: R, z }`. Finally it asserts the aggregate itself verifies
/// (RFC 8032); a failure there after every partial verified is an internal bug.
pub fn aggregate(
    shares: &[SignatureShare],
    commitments: &[SigningCommitments],
    public: &PublicKeyPackage,
    msg: &[u8],
) -> Result<Signature, Error> {
    let ids: Vec<Identifier> = commitments.iter().map(|c| c.id).collect();
    validate_identifier_set(&ids)?;
    if ids.len() < public.threshold as usize {
        return Err(Error::InvalidThreshold);
    }

    let prefix = RhoPrefix::new(commitments, public, msg);
    let r = compute_group_commitment(commitments, &prefix);
    let challenge = compute_challenge(&r, public, msg);

    // Verify every partial against X_j BEFORE summing; name the first culprit.
    for share in shares {
        crate::verify::verify_one_share(share, commitments, &ids, &prefix, &challenge, public)?;
    }

    // Only verified partials are summed: z = Σ z_j.
    let mut z = GScalar::from_scalar(Scalar::ZERO);
    for share in shares {
        z = z + share.z;
    }
    let sig = Signature { r, z };

    // The aggregate must verify under RFC 8032. Reaching here with a bad
    // signature after every partial verified is an internal bug.
    if let Err(e) = crate::verify::verify(&public.group_public, msg, &sig) {
        debug_assert!(false, "aggregate failed RFC 8032 verify after all partials passed: {e:?}");
        return Err(Error::InvalidSignature);
    }
    Ok(sig)
}

/// The binding-factor input prefix `group_public_enc ‖ H4(msg) ‖ H5(commitment_list)`
/// (RFC 9591 §4.4; `frost-core-2.2.0/src/lib.rs:415-447`), precomputed once so the
/// per-signer `ρ_j = H1(prefix ‖ id_enc(j))` shares one encoding across `sign`,
/// `aggregate`, and `verify`.
///
/// NOTE: phase1-spec §4.2's shorthand `ρ_j = H1(msg_hash ‖ com_hash ‖ id_enc)`
/// omits the `group_public_enc` prefix; the RFC and the oracle source include it.
/// Verified against the source; the intermediate KATs (§7.1) are the guard.
pub(crate) struct RhoPrefix(Vec<u8>);

impl RhoPrefix {
    pub(crate) fn new(
        commitments: &[SigningCommitments],
        public: &PublicKeyPackage,
        msg: &[u8],
    ) -> Self {
        let mut v = Vec::with_capacity(32 + 64 + 64);
        v.extend_from_slice(&public.group_public.to_compressed());
        v.extend_from_slice(&ciphersuite::h4(msg));
        v.extend_from_slice(&ciphersuite::h5(&ciphersuite::encode_commitment_list(commitments)));
        RhoPrefix(v)
    }

    /// `ρ_j = H1(group_public_enc ‖ msg_hash ‖ com_hash ‖ id_enc(j))`.
    pub(crate) fn binding_factor(&self, id: Identifier) -> GScalar {
        let id_enc = id.as_scalar().to_bytes();
        ciphersuite::h1(&[self.0.as_slice(), id_enc.as_slice()])
    }
}

/// Group commitment `R = Σ_j (D_j + ρ_j·E_j)` (phase1-spec §4.2 step 4).
pub(crate) fn compute_group_commitment(
    commitments: &[SigningCommitments],
    prefix: &RhoPrefix,
) -> GElement {
    let mut r = GElement::identity();
    for c in commitments {
        let rho_j = prefix.binding_factor(c.id);
        r = r + c.hiding + c.binding.scalar_mul(&rho_j);
    }
    r
}

/// Challenge `c = H2(R_enc ‖ group_public_enc ‖ msg)` — no contextString, so it
/// equals the RFC 8032 challenge (phase1-spec §4.2 step 5).
pub(crate) fn compute_challenge(
    group_commitment: &GElement,
    public: &PublicKeyPackage,
    msg: &[u8],
) -> GScalar {
    let r_enc = group_commitment.to_compressed();
    let a_enc = public.group_public.to_compressed();
    ciphersuite::h2(&[r_enc.as_slice(), a_enc.as_slice(), msg])
}

/// Lagrange interpolation coefficient `λ_i` for `i` over the signer set, evaluated
/// at `x = 0` (RFC 9591 §4.2): `λ_i = Π_{j≠i} x_j / (x_j − x_i)`. Matches
/// `frost-core-2.2.0/src/lib.rs:297-333` `compute_lagrange_coefficient` with
/// `x = None`. Returns `Err(InvalidEncoding)` if `i` is not in `set`; the
/// denominator is nonzero because `validate_identifier_set` rejected duplicates.
pub(crate) fn lagrange_coefficient(i: Identifier, set: &[Identifier]) -> Result<GScalar, Error> {
    let xi = i.as_scalar();
    let one = GScalar::from_scalar(Scalar::ONE);
    let mut num = one;
    let mut den = one;
    let mut found = false;
    for &j in set {
        if j == i {
            found = true;
            continue;
        }
        let xj = j.as_scalar();
        num = num * xj;
        den = den * (xj - xi);
    }
    if !found {
        return Err(Error::InvalidEncoding("signer not in commitment set"));
    }
    Ok(num * den.invert())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::Identifier;
    use crate::keygen::trusted_dealer_keygen;
    use rand::rngs::OsRng;

    // End-to-end smoke for Session 1.1: keygen → commit → sign produces a partial
    // for 2-of-3, exercising binding factors, the group commitment, the challenge,
    // and the Lagrange coefficient. Full RFC 8032 verification arrives in 1.2.
    #[test]
    fn commit_and_sign_2_of_3_produces_a_partial() {
        let mut rng = OsRng;
        let ids: Vec<Identifier> = (1..=3).map(|i| Identifier::try_from_u64(i).unwrap()).collect();
        let (key_packages, public) = trusted_dealer_keygen(2, &ids, &mut rng).unwrap();

        // Signer set {1, 2}.
        let signer_ids = [ids[0], ids[1]];
        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        for id in signer_ids {
            let kp = &key_packages[&id];
            let (n, c) = commit(id, &kp.signing_share, &mut rng);
            commitments.push(c);
            nonces.push(n);
        }

        let msg = b"frost-ed25519-kit session 1.1";
        for (i, id) in signer_ids.iter().enumerate() {
            let kp = &key_packages[id];
            // `nonces` consumed by value (single-use).
            let n = nonces.remove(0);
            let share = sign(&kp.signing_share, n, *id, &commitments, &public, msg).unwrap();
            assert_eq!(share.id, signer_ids[i]);
        }
    }

    #[test]
    fn sign_rejects_signer_outside_the_commitment_set() {
        let mut rng = OsRng;
        let ids: Vec<Identifier> = (1..=3).map(|i| Identifier::try_from_u64(i).unwrap()).collect();
        let (key_packages, public) = trusted_dealer_keygen(2, &ids, &mut rng).unwrap();

        // Commit only for {1, 2}, but try to sign as identifier 3.
        let signer_ids = [ids[0], ids[1]];
        let mut commitments = Vec::new();
        for id in signer_ids {
            let kp = &key_packages[&id];
            let (_n, c) = commit(id, &kp.signing_share, &mut rng);
            commitments.push(c);
        }
        let outsider = ids[2];
        let kp = &key_packages[&outsider];
        let (n, _c) = commit(outsider, &kp.signing_share, &mut rng);
        // `SignatureShare` has no `Debug` (GScalar has none), so match rather than
        // `unwrap_err`, which would require the Ok type to be `Debug`.
        let result = sign(&kp.signing_share, n, outsider, &commitments, &public, b"x");
        assert!(matches!(result, Err(Error::InvalidEncoding(_))));
    }

    #[test]
    fn commit_is_hedged_distinct_hiding_and_binding() {
        let mut rng = OsRng;
        let id = Identifier::try_from_u64(7).unwrap();
        let share = SigningShare::from_canonical_bytes({
            let mut b = [0u8; 32];
            b[0] = 9;
            b
        })
        .unwrap();
        let (_n, c) = commit(id, &share, &mut rng);
        // The two independent random hedges must yield different commitments.
        assert_ne!(c.hiding, c.binding);
    }

    // Full keygen → commit → sign for the `signers` of a `t`-of-`n` group, returning
    // the partials, the commitment set, and the public package.
    fn run_round(
        t: u16,
        n: u64,
        signers: &[u64],
        msg: &[u8],
    ) -> (Vec<SignatureShare>, Vec<SigningCommitments>, PublicKeyPackage) {
        let mut rng = OsRng;
        let ids: Vec<Identifier> = (1..=n).map(|i| Identifier::try_from_u64(i).unwrap()).collect();
        let (key_packages, public) = trusted_dealer_keygen(t, &ids, &mut rng).unwrap();
        let signer_ids: Vec<Identifier> = signers
            .iter()
            .map(|&i| Identifier::try_from_u64(i).unwrap())
            .collect();

        let mut commitments = Vec::new();
        let mut nonces = Vec::new();
        for &id in &signer_ids {
            let kp = &key_packages[&id];
            let (nce, c) = commit(id, &kp.signing_share, &mut rng);
            commitments.push(c);
            nonces.push(nce);
        }
        let mut shares = Vec::new();
        for (&id, nce) in signer_ids.iter().zip(nonces) {
            let kp = &key_packages[&id];
            shares.push(sign(&kp.signing_share, nce, id, &commitments, &public, msg).unwrap());
        }
        (shares, commitments, public)
    }

    #[test]
    fn end_to_end_2_of_3_signature_verifies() {
        let msg = b"phase1 session 1.2 end-to-end";
        let (shares, commitments, public) = run_round(2, 3, &[1, 2], msg);
        let sig = aggregate(&shares, &commitments, &public, msg).unwrap();
        assert!(crate::verify::verify(&public.group_public, msg, &sig).is_ok());
        // 64-byte R_enc ‖ z_enc round-trips.
        let decoded = Signature::from_bytes(sig.to_bytes()).unwrap();
        assert!(sig == decoded);
    }

    #[test]
    fn end_to_end_3_of_5_signature_verifies() {
        let msg = b"phase1 session 1.2 three of five";
        let (shares, commitments, public) = run_round(3, 5, &[2, 3, 5], msg);
        let sig = aggregate(&shares, &commitments, &public, msg).unwrap();
        assert!(crate::verify::verify(&public.group_public, msg, &sig).is_ok());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let msg = b"tamper";
        let (shares, commitments, public) = run_round(2, 3, &[1, 3], msg);
        let sig = aggregate(&shares, &commitments, &public, msg).unwrap();
        assert!(crate::verify::verify(&public.group_public, msg, &sig).is_ok());
        // A different message must not verify under the same signature.
        assert!(matches!(
            crate::verify::verify(&public.group_public, b"tamper!", &sig),
            Err(Error::InvalidSignature)
        ));
        // Corrupting z by one breaks the equation.
        let bad = Signature {
            r: sig.r,
            z: sig.z + GScalar::from_scalar(Scalar::ONE),
        };
        assert!(matches!(
            crate::verify::verify(&public.group_public, msg, &bad),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn aggregate_names_the_culprit_on_a_bad_partial() {
        let msg = b"culprit";
        let (mut shares, commitments, public) = run_round(2, 3, &[1, 2], msg);
        let culprit = Identifier::try_from_u64(2).unwrap();
        for s in &mut shares {
            if s.id == culprit {
                s.z = s.z + GScalar::from_scalar(Scalar::ONE);
            }
        }
        assert!(matches!(
            aggregate(&shares, &commitments, &public, msg),
            Err(Error::Culprit(id)) if id == culprit
        ));
        // The honest set (re-run) still aggregates and verifies.
        let (honest, c2, p2) = run_round(2, 3, &[1, 2], msg);
        assert!(aggregate(&honest, &c2, &p2, msg).is_ok());
    }

    #[test]
    fn verify_share_accepts_every_honest_partial() {
        let msg = b"honest shares";
        let (shares, commitments, public) = run_round(3, 5, &[1, 2, 4], msg);
        for s in &shares {
            assert!(crate::verify::verify_share(s, &commitments, &public, msg).is_ok());
        }
    }
}
