//! Differential + functional gate for the Pedersen DKG (phase2-spec §8.2).
//!
//! **There is no official RFC 9591 KAT for DKG** — DKG is not normative in
//! RFC 9591, so there is no published vector to assert against. Correctness rests
//! on three gates, in the Phase 1 spirit: the deterministic PoK-challenge pin
//! (`tests/dkg_pok_pin.rs`, Session 2.1), the interop-vs-`frost-ed25519` checks
//! below (both directions), and the functional end-to-end property (full DKG →
//! reconstruct → verifying-share match → DKG→sign→verify under both verifiers).
//!
//! **On byte-for-byte DKG agreement (phase2-spec §8.2):** unlike Phase 1's
//! signing, the DKG draws polynomial coefficients *and* a PoK nonce per
//! participant, and `frost-core` uses a *hedged* PoK nonce
//! (`H3(random ‖ encode(a_0))`) where the `frost-core` oracle uses a plain random
//! one — so byte-identical round-1 packages are neither expected nor a goal.
//! Matching the oracle's exact RNG draw order would couple this code to the
//! oracle's internals; it is an explicit non-goal. The required, robust gate is
//! **interop** (our packages verify under their verifier, and theirs under ours —
//! the PoK encoding and commitment format agree) plus the **functional** property
//! (the DKG output is a valid FROST key). That is what this file asserts.

use std::collections::BTreeMap;

use frost_core as fc;
use frost_ed25519 as ed;

use fc::group::{GElement, GScalar, Identifier};
use fc::vss::{Commitments, verifying_share};

use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn to32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    a
}

/// A `GScalar` from a small unsigned integer (canonical little-endian).
fn scalar(v: u8) -> GScalar {
    let mut b = [0u8; 32];
    b[0] = v;
    GScalar::from_canonical_bytes(b).expect("small value is canonical")
}

/// Lagrange-interpolate `f(0)` from points `(x_i, y_i)`:
/// `f(0) = Σ_i y_i · Π_{j≠i} x_j / (x_j − x_i)`.
fn interpolate_at_zero(points: &[(Identifier, GScalar)]) -> GScalar {
    let mut acc = scalar(0);
    for (i, (id_i, y_i)) in points.iter().enumerate() {
        let xi = id_i.as_scalar();
        let mut num = scalar(1);
        let mut den = scalar(1);
        for (j, (id_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = id_j.as_scalar();
            num = num * xj;
            den = den * (xj - xi);
        }
        let lambda = num * den.invert();
        acc = acc + *y_i * lambda;
    }
    acc
}

// --- Cross-library round1::Package converters (values, not bytes) -----------
// We move the *values* (commitment points, PoK R/μ) between the two libraries'
// types via their public constructors, rather than matching either library's
// exact serialized byte layout (a deliberate non-goal, see the header).

/// Rebuild a `frost-ed25519` round-1 package from a `frost-core` one.
fn fc_to_ed_package(pkg: &fc::dkg::round1::Package) -> ed::keys::dkg::round1::Package {
    let coeff_bytes: Vec<Vec<u8>> = pkg
        .commitments
        .0
        .iter()
        .map(|p| p.to_compressed().to_vec())
        .collect();
    let commitment = ed::keys::VerifiableSecretSharingCommitment::deserialize(coeff_bytes).unwrap();
    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&pkg.pok.r_commitment.to_compressed());
    sig.extend_from_slice(&pkg.pok.response.to_bytes());
    let pok = ed::Signature::deserialize(&sig).unwrap();
    ed::keys::dkg::round1::Package::new(commitment, pok)
}

/// Rebuild a `frost-core` round-1 package from a `frost-ed25519` one.
fn ed_to_fc_package(pkg: &ed::keys::dkg::round1::Package) -> fc::dkg::round1::Package {
    let points: Vec<GElement> = pkg
        .commitment()
        .serialize()
        .unwrap()
        .iter()
        .map(|b| GElement::from_compressed(to32(b)).unwrap())
        .collect();
    let sig = pkg.proof_of_knowledge().serialize().unwrap();
    fc::dkg::round1::Package {
        commitments: Commitments(points),
        pok: fc::dkg::ProofOfKnowledge {
            r_commitment: GElement::from_compressed(to32(&sig[0..32])).unwrap(),
            response: GScalar::from_canonical_bytes(to32(&sig[32..64])).unwrap(),
        },
    }
}

// --- Direction A: our packages, their verifier ------------------------------

/// `frost-ed25519`'s `part2` (the verifier) must accept `frost-core`'s round-1
/// packages: a `frost-core` participant's PoK and commitment are valid under the
/// oracle. We run the oracle as participant 1 of a 2-of-3 run and feed it
/// `frost-core` participants 2 and 3 as the other round-1 packages.
#[test]
fn direction_a_our_packages_their_verifier() {
    let mut rng = StdRng::seed_from_u64(0xDA_2026);
    let ed_id1 = ed::Identifier::try_from(1u16).unwrap();
    let (ed_secret1, _ed_pkg1) = ed::keys::dkg::part1(ed_id1, 3, 2, &mut rng).unwrap();

    let mut others = BTreeMap::new();
    for lab in [2u16, 3u16] {
        let fc_id = Identifier::try_from_u64(lab as u64).unwrap();
        let (_s, fc_pkg) = fc::dkg::part1(fc_id, 2, 3, &mut rng).unwrap();
        others.insert(ed::Identifier::try_from(lab).unwrap(), fc_to_ed_package(&fc_pkg));
    }

    assert!(
        ed::keys::dkg::part2(ed_secret1, &others).is_ok(),
        "frost-ed25519 rejected frost-core's round-1 PoK/commitment"
    );
}

// --- Direction B: their packages, our verifier ------------------------------

/// `frost-core`'s `part2` (our verifier) must accept `frost-ed25519`'s round-1
/// packages: the oracle's PoK and commitment are valid under our verification.
/// We run `frost-core` as participant 1 of a 2-of-3 run and feed it oracle
/// participants 2 and 3 as the other round-1 packages.
#[test]
fn direction_b_their_packages_our_verifier() {
    let mut rng = StdRng::seed_from_u64(0xDB_2026);
    let fc_id1 = Identifier::try_from_u64(1).unwrap();
    let (fc_secret1, _fc_pkg1) = fc::dkg::part1(fc_id1, 2, 3, &mut rng).unwrap();

    let mut peers = BTreeMap::new();
    for lab in [2u16, 3u16] {
        let ed_id = ed::Identifier::try_from(lab).unwrap();
        let (_s, ed_pkg) = ed::keys::dkg::part1(ed_id, 3, 2, &mut rng).unwrap();
        peers.insert(
            Identifier::try_from_u64(lab as u64).unwrap(),
            ed_to_fc_package(&ed_pkg),
        );
    }

    assert!(
        fc::dkg::part2(fc_secret1, &peers).is_ok(),
        "frost-core rejected frost-ed25519's round-1 PoK/commitment"
    );
}

// --- Functional: full frost-core DKG ----------------------------------------

/// The other participants' round-1 packages, `self` removed (the exclude-self
/// input convention of `part2`/`part3`).
fn peers_of(
    all: &BTreeMap<Identifier, fc::dkg::round1::Package>,
    me: Identifier,
) -> BTreeMap<Identifier, fc::dkg::round1::Package> {
    all.iter()
        .filter(|(id, _)| **id != me)
        .map(|(&id, pkg)| (id, pkg.clone()))
        .collect()
}

/// Drive a full `t`-of-`n` `frost-core` DKG in process via the public API.
/// Returns each participant's `KeyPackage`, each derived `PublicKeyPackage`, and
/// every broadcast round-1 package (for the independent verifying-share check).
#[allow(clippy::type_complexity)]
fn run_dkg(
    threshold: u16,
    n: u16,
    seed: u64,
) -> (
    BTreeMap<Identifier, fc::KeyPackage>,
    BTreeMap<Identifier, fc::PublicKeyPackage>,
    BTreeMap<Identifier, fc::dkg::round1::Package>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let ids: Vec<Identifier> = (1..=n as u64)
        .map(|i| Identifier::try_from_u64(i).unwrap())
        .collect();

    let mut secrets1 = BTreeMap::new();
    let mut round1_all = BTreeMap::new();
    for &id in &ids {
        let (s1, pkg) = fc::dkg::part1(id, threshold, n, &mut rng).unwrap();
        secrets1.insert(id, s1);
        round1_all.insert(id, pkg);
    }

    let mut secrets2 = BTreeMap::new();
    let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, fc::dkg::round2::Package>> =
        ids.iter().map(|&id| (id, BTreeMap::new())).collect();
    for &id in &ids {
        let s1 = secrets1.remove(&id).unwrap();
        let (s2, outgoing) = fc::dkg::part2(s1, &peers_of(&round1_all, id)).unwrap();
        secrets2.insert(id, s2);
        for (recipient, pkg) in outgoing {
            inbox.get_mut(&recipient).unwrap().insert(id, pkg);
        }
    }

    let mut key_packages = BTreeMap::new();
    let mut public_packages = BTreeMap::new();
    for &id in &ids {
        let received = inbox.remove(&id).unwrap();
        let (kp, pkp) =
            fc::dkg::part3(&secrets2[&id], &peers_of(&round1_all, id), &received).unwrap();
        key_packages.insert(id, kp);
        public_packages.insert(id, pkp);
    }
    (key_packages, public_packages, round1_all)
}

/// The functional property (phase2-spec §8.2): for a full `frost-core` DKG —
/// (i) any `t` signing shares reconstruct a group secret whose `·G` is
/// `group_public`; (ii) every `verifying_share` equals `vss::verifying_share`
/// over the summed dealer commitments; (iii) the DKG `KeyPackage`s drive the
/// frozen Phase 1 `commit`/`sign`/`aggregate`, and the signature verifies under
/// both `verify.rs` and `frost-ed25519`'s verifier.
fn functional(threshold: u16, n: u16, seed: u64, msg: &[u8]) {
    let t = threshold as usize;
    let (kps, pkps, round1_all) = run_dkg(threshold, n, seed);
    let ids: Vec<Identifier> = kps.keys().copied().collect();
    // All participants agree (proven in Session 2.2); use participant 1's view.
    let pkp = &pkps[&ids[0]];

    // (i) Reconstruct from the first t shares; (a_0)·G == group_public.
    let shares: Vec<(Identifier, GScalar)> = ids
        .iter()
        .map(|id| (*id, kps[id].signing_share.to_scalar()))
        .collect();
    let a0 = interpolate_at_zero(&shares[..t]);
    assert_eq!(
        GElement::generator().scalar_mul(&a0),
        pkp.group_public,
        "{t} DKG shares must reconstruct the group key"
    );

    // (ii) Verifying-share match: sum the dealer commitments coefficient-wise and
    // recompute every verifying share independently of part3.
    let mut agg = vec![GElement::identity(); t];
    for pkg in round1_all.values() {
        for (k, slot) in agg.iter_mut().enumerate() {
            *slot = *slot + pkg.commitments.0[k];
        }
    }
    let agg = Commitments(agg);
    assert_eq!(agg.0[0], pkp.group_public, "Σ φ_{{j,0}} must equal group_public");
    for ell in &ids {
        assert_eq!(
            verifying_share(*ell, &agg),
            pkp.verifying_shares[ell],
            "verifying share mismatch vs summed commitments"
        );
    }

    // (iii) DKG -> frozen sign -> verify, cross-verified under frost-ed25519.
    let signers = &ids[..t];
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5167_3017);
    let mut commitments = Vec::new();
    let mut nonces: BTreeMap<Identifier, fc::secret::SigningNonces> = BTreeMap::new();
    for &id in signers {
        let (nonce, com) = fc::sign::commit(id, &kps[&id].signing_share, &mut rng);
        commitments.push(com);
        nonces.insert(id, nonce);
    }
    let mut sig_shares = Vec::new();
    for &id in signers {
        let nonce = nonces.remove(&id).unwrap();
        let share =
            fc::sign::sign(&kps[&id].signing_share, nonce, id, &commitments, pkp, msg).unwrap();
        sig_shares.push(share);
    }
    let sig = fc::sign::aggregate(&sig_shares, &commitments, pkp, msg).unwrap();

    assert!(
        fc::verify::verify(&pkp.group_public, msg, &sig).is_ok(),
        "DKG signature failed frost-core verification"
    );
    let vk = ed::VerifyingKey::deserialize(&pkp.group_public.to_compressed()).unwrap();
    let ed_sig = ed::Signature::deserialize(&sig.to_bytes()).unwrap();
    assert!(
        vk.verify(msg, &ed_sig).is_ok(),
        "DKG signature failed frost-ed25519 verification"
    );
}

#[test]
fn functional_dkg_2_of_3() {
    functional(2, 3, 0x20F3, b"frost-core dkg 2-of-3");
}

#[test]
fn functional_dkg_3_of_5() {
    functional(3, 5, 0x30F5, b"frost-core dkg 3-of-5");
}

// (n, t, msg, seed) with 2 ≤ t ≤ n ≤ 8.
fn func_strategy() -> impl Strategy<Value = (u16, u16, Vec<u8>, u64)> {
    (2u16..=8).prop_flat_map(|n| {
        (
            Just(n),
            2u16..=n,
            proptest::collection::vec(any::<u8>(), 0..32),
            any::<u64>(),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, max_shrink_iters: 32, .. ProptestConfig::default() })]

    /// The functional property holds across ≥1,000 randomized (t, n, msg, seed)
    /// cases over 2 ≤ t ≤ n ≤ 8 (phase2-spec §8.2; the DKG is heavier than
    /// signing, so 1,000 cases is the stated sufficient bound).
    #[test]
    fn functional_dkg_property((n, t, msg, seed) in func_strategy()) {
        functional(t, n, seed, &msg);
    }
}
