//! Deterministic pin of the DKG proof-of-knowledge challenge encoding
//! (phase2-spec §8.1).
//!
//! There is **no official RFC 9591 KAT for DKG** — DKG is not normative in
//! RFC 9591 — so there is no published challenge vector to assert against. The
//! DKG introduces exactly one new hash-input encoding: the PoK challenge
//! `c_i = H_dkg(id_i ‖ φ_{i,0} ‖ R_i)`. This is precisely the one-byte-prefix
//! risk surface the Session 1.1 rho correction exposed, so it is pinned here,
//! against the `frost-ed25519` 2.2.0 oracle, **before** the full-DKG tests, so a
//! deviation localizes at the challenge instead of surfacing as an
//! unattributable DKG verification failure three rounds downstream.
//!
//! Two assertions:
//! 1. **Oracle pin** — take an honest proof produced by `frost-ed25519`'s own
//!    `dkg::part1`, recompute the challenge with `frost-core`'s
//!    `pok_challenge`, and check the oracle's proof verifies under it
//!    (`μ_i·G == R_i + c_i·φ_{i,0}`). The oracle's proof was generated with the
//!    oracle's own (private) challenge; it verifies under ours **iff** the two
//!    encodings agree byte-for-byte. A one-byte deviation in label or input
//!    order changes `c_i` and breaks the equation.
//! 2. **Self-consistency** — an honestly generated `frost-core` proof satisfies
//!    `μ_i·G == R_i + c_i·φ_{i,0}` with `c_i` recomputed from its own inputs.

use std::convert::TryInto;

use frost_core::dkg::{part1, pok_challenge};
use frost_core::group::{GElement, GScalar, Identifier};

use frost_ed25519 as ed;
use rand::SeedableRng;
use rand::rngs::StdRng;

/// `μ·G == R + c·φ0` — the Schnorr PoK verification equation (additive form),
/// with `c` recomputed by `frost-core`'s `pok_challenge` over `(id, φ0, R)`.
fn pok_verifies(id: Identifier, phi0: &GElement, r: &GElement, mu: &GScalar) -> bool {
    let c = pok_challenge(id, phi0, r);
    let lhs = GElement::generator().scalar_mul(mu);
    let rhs = *r + phi0.scalar_mul(&c);
    lhs == rhs
}

#[test]
fn pok_challenge_pins_against_frost_ed25519() {
    // Drive the oracle's DKG part1 for a fixed participant in a 2-of-3 run.
    let mut rng = StdRng::seed_from_u64(0xD46_2026);
    let ed_id = ed::Identifier::try_from(1u16).unwrap();
    let (_ed_secret, ed_pkg) = ed::keys::dkg::part1(ed_id, 3, 2, &mut rng).unwrap();

    // Extract the oracle's (id, φ_{i,0}, R_i, μ_i) in their canonical encodings.
    // Signature::serialize is R_enc(32) ‖ μ_enc(32); commitment.serialize()[0] is φ_{i,0}.
    let sig = ed_pkg.proof_of_knowledge().serialize().unwrap();
    let r_bytes: [u8; 32] = sig[0..32].try_into().unwrap();
    let mu_bytes: [u8; 32] = sig[32..64].try_into().unwrap();
    let phi0_bytes: [u8; 32] = ed_pkg.commitment().serialize().unwrap()[0]
        .as_slice()
        .try_into()
        .unwrap();
    let id_bytes: [u8; 32] = ed_id.serialize().try_into().unwrap();

    // Decode through the frozen group layer (rejects non-canonical / non-prime-order).
    let id = Identifier::from_canonical_bytes(id_bytes).unwrap();
    let phi0 = GElement::from_compressed(phi0_bytes).unwrap();
    let r = GElement::from_compressed(r_bytes).unwrap();
    let mu = GScalar::from_canonical_bytes(mu_bytes).unwrap();

    // The oracle's proof verifies under our recomputed challenge iff our challenge
    // encoding matches frost-ed25519's byte-for-byte.
    assert!(
        pok_verifies(id, &phi0, &r, &mu),
        "frost-core PoK challenge encoding deviates from frost-ed25519 2.2.0"
    );
}

#[test]
fn frost_core_pok_is_self_consistent() {
    let mut rng = StdRng::seed_from_u64(0x5E1F);
    let id = Identifier::try_from_u64(1).unwrap();
    let (_secret, pkg) = part1(id, 2, 3, &mut rng).unwrap();

    let phi0 = pkg.commitments.0[0];
    assert!(
        pok_verifies(id, &phi0, &pkg.pok.r_commitment, &pkg.pok.response),
        "honestly generated frost-core PoK failed its own verification equation"
    );
}
