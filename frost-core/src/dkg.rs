//! Pedersen verifiable distributed key generation (phase2-spec §4).
//!
//! Replaces the trusted dealer's *trust assumption* (see [`crate::keygen`]) with
//! a three-round protocol in which no single party ever holds the group secret.
//! It mirrors the `frost-core`/`frost-ed25519` `keys::dkg` API so the Phase 2
//! differential (phase2-spec §8.2) is clean, and it emits the **identical**
//! Phase 0 [`KeyPackage`] / [`PublicKeyPackage`] types so the frozen Phase 1
//! signing path consumes its output unchanged.
//!
//! This file (Session 2.1) implements **round 1 only**: each participant samples
//! a degree-`(t-1)` polynomial `f_i`, publishes the Feldman commitment
//! `φ_{i,k} = a_{i,k}·G`, and proves knowledge of its constant term `a_{i,0}`
//! with a Schnorr proof of knowledge — the rogue-key defence (Komlo–Goldberg §5,
//! Gennaro et al. biasing attack). `part2`/`part3` land in Session 2.2.
//!
//! The one new hash-input encoding is the PoK challenge `H_dkg`; its label and
//! input order were **verified against `frost-ed25519` 2.2.0 source**, recorded
//! as named constants in [`crate::ciphersuite`], and are pinned deterministically
//! against the oracle by `tests/dkg_pok_pin.rs` before the full DKG is built
//! (phase2-spec §5).

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::ciphersuite;
use crate::error::Error;
use crate::group::{GElement, GScalar, Identifier};
use crate::vss::Commitments;

/// A Schnorr proof of knowledge of the polynomial's constant term `a_{i,0}`
/// (phase2-spec §4): `σ_i = (R_i, μ_i)` with `R_i = k_i·G`,
/// `c_i = H_dkg(id_i ‖ φ_{i,0} ‖ R_i)`, `μ_i = k_i + a_{i,0}·c_i`. Verified by
/// checking `μ_i·G == R_i + c_i·φ_{i,0}`.
///
/// Carries **no secret**: `R_i` is a nonce commitment and `μ_i` is a Schnorr
/// response. It is broadcast in [`round1::Package`]; both fields are public.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProofOfKnowledge {
    /// `R_i = k_i·G` — the commitment to the (hedged, single-use) PoK nonce.
    pub r_commitment: GElement,
    /// `μ_i = k_i + a_{i,0}·c_i` — the Schnorr response.
    pub response: GScalar,
}

// Both fields are public proof material (a nonce commitment and a Schnorr
// response); a non-redacting Debug over their canonical encodings is safe.
// `GScalar` (frozen) has no Debug, so the response is printed as hex here.
impl core::fmt::Debug for ProofOfKnowledge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProofOfKnowledge { r_commitment: ")?;
        write!(f, "{:?}", self.r_commitment)?;
        f.write_str(", response: 0x")?;
        for byte in self.response.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(" }")
    }
}

/// The DKG PoK challenge `c_i = H_dkg(id_i ‖ φ_{i,0}_enc ‖ R_i_enc)` (phase2-spec
/// §4/§5). The input order — identifier, then the constant-term commitment
/// `φ_{i,0}`, then the nonce commitment `R_i`, each length-exactly 32 bytes — is
/// verified against `frost-core-2.2.0/src/keys/dkg.rs:412-430` (`challenge`), and
/// the `contextString ‖ "dkg"` prefix + wide reduction live in
/// [`ciphersuite::hdkg`]. This is the single new encoding; `tests/dkg_pok_pin.rs`
/// pins it against `frost-ed25519` before the full DKG runs.
pub fn pok_challenge(id: Identifier, phi0: &GElement, r_commitment: &GElement) -> GScalar {
    let id_enc = id.as_scalar().to_bytes();
    let phi0_enc = phi0.to_compressed();
    let r_enc = r_commitment.to_compressed();
    ciphersuite::hdkg(&[&id_enc, &phi0_enc, &r_enc])
}

/// DKG round 1 structures (phase2-spec §4).
pub mod round1 {
    use super::*;

    /// Kept private by the participant between rounds. Holds the secret
    /// polynomial `f_i`; consumed by `part2`. The coefficients are wrapped in
    /// [`Zeroizing`] so they are wiped on drop; the type carries no `Serialize`
    /// and only a redacting `Debug` (phase2-spec §4).
    pub struct SecretPackage {
        /// Coefficients `(a_{i,0}, …, a_{i,t-1})` of `f_i` (degree `t-1`). Read by
        /// `part2` (Session 2.2) to evaluate `f_i(ℓ)` for every recipient; held
        /// (zeroizing) between rounds. The same forward-reference pattern as the
        /// Phase 0 `SigningNonces` fields.
        #[allow(dead_code)]
        pub(crate) coefficients: Zeroizing<Vec<Scalar>>,
        /// This participant's identifier.
        pub(crate) id: Identifier,
        /// The minimum number of signers `t`.
        pub(crate) threshold: u16,
        /// The total number of signers `n`.
        pub(crate) max_signers: u16,
    }

    // Redacting Debug: never prints coefficient bytes (the secret polynomial).
    impl core::fmt::Debug for SecretPackage {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("round1::SecretPackage")
                .field("coefficients", &"<redacted>")
                .field("id", &self.id)
                .field("threshold", &self.threshold)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    /// Broadcast by the participant to all others between round 1 and round 2.
    /// Carries **no secret**: the Feldman commitments `φ_{i,0..t-1} = a_{i,k}·G`
    /// and the proof of knowledge of `a_{i,0}`.
    pub struct Package {
        /// `φ_{i,k} = a_{i,k}·G` for `k = 0..t-1`; `commitments.0[0]` is `φ_{i,0}`,
        /// the participant's public contribution to the group key.
        pub commitments: Commitments,
        /// Schnorr proof that the participant knows `a_{i,0}` (rogue-key defence).
        pub pok: ProofOfKnowledge,
    }

    // All fields are public; `vss::Commitments` (frozen) has no Debug, so the
    // commitment points are listed via their own `GElement` Debug.
    impl core::fmt::Debug for Package {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("round1::Package")
                .field("commitments", &self.commitments.0)
                .field("pok", &self.pok)
                .finish()
        }
    }
}

/// Round 1: sample `f_i` (degree `t-1`), commit `φ_{i,k} = a_{i,k}·G`, and prove
/// knowledge of the constant term `a_{i,0}` (phase2-spec §4).
///
/// The PoK nonce is **hedged** against RNG failure (amendment §3, applied to the
/// PoK): `k_i = H3(random_bytes(32) ‖ encode(a_{i,0}))`. Mixing the secret
/// `a_{i,0}` into the nonce means a fully predictable RNG still cannot collide
/// `k_i` across distinct constant terms. `k_i` is single-use and zeroized the
/// moment the response is formed.
///
/// Rejects `threshold == 0` and `threshold > max_signers` with `InvalidThreshold`.
/// `id` is an [`Identifier`], so it is already validated nonzero by the frozen
/// group layer; the full participant-set (zero/duplicate) check runs once all
/// round-1 packages are present, in `part2`.
pub fn part1(
    id: Identifier,
    threshold: u16,
    max_signers: u16,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(round1::SecretPackage, round1::Package), Error> {
    if threshold == 0 || threshold > max_signers {
        return Err(Error::InvalidThreshold);
    }

    // Round 1, Step 1: sample t coefficients (a_{i,0}, …, a_{i,t-1}) ← Z_q.
    let t = threshold as usize;
    let coefficients: Vec<Scalar> = (0..t).map(|_| Scalar::random(rng)).collect();

    // Round 1, Step 3: φ_{i,k} = a_{i,k}·G. Only public points leave here.
    let g = GElement::generator();
    let commitment_points: Vec<GElement> = coefficients
        .iter()
        .map(|c| g.scalar_mul(&GScalar::from_scalar(*c)))
        .collect();
    let commitments = Commitments(commitment_points);
    // t >= 1 guarantees a constant term; φ_{i,0} is the public contribution.
    let phi0 = commitments.0[0];

    // Round 1, Step 2: proof of knowledge of a_{i,0}, with a hedged PoK nonce.
    // encode(a_{i,0}): canonical 32-byte little-endian scalar — a work-path read
    // of the secret constant term; the buffer is zeroized below.
    let a0 = coefficients[0];
    let mut a0_enc = a0.to_bytes();
    let mut rand = [0u8; 32];
    rng.fill_bytes(&mut rand);

    // k_i = H3(random ‖ encode(a_{i,0})); held in Zeroizing so the single-use
    // nonce is wiped on drop the moment this function returns.
    let k = Zeroizing::new(ciphersuite::h3(&[rand.as_slice(), a0_enc.as_slice()]).as_scalar());
    let k_scalar = GScalar::from_scalar(*k);
    let r_commitment = g.scalar_mul(&k_scalar);
    let c = pok_challenge(id, &phi0, &r_commitment);
    // μ_i = k_i + a_{i,0}·c_i.
    let response = k_scalar + GScalar::from_scalar(a0) * c;

    a0_enc.zeroize();
    rand.zeroize();

    let secret = round1::SecretPackage {
        coefficients: Zeroizing::new(coefficients),
        id,
        threshold,
        max_signers,
    };
    let package = round1::Package {
        commitments,
        pok: ProofOfKnowledge {
            r_commitment,
            response,
        },
    };
    Ok((secret, package))
}
