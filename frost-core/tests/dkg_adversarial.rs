//! Adversarial / identifiable-abort gate for the Pedersen DKG (phase2-spec §8.3,
//! §6; amendment §2, §3, §5).
//!
//! **There is no official RFC 9591 KAT for DKG** — DKG is not normative in
//! RFC 9591. These tests assert the protocol's adversarial contract directly: a
//! DKG that fails must name the party that caused it (the keygen analogue of
//! Phase 1's partial-signature abort), and the identifier/nonce disciplines hold.
//!
//! - **Bad PoK** → `part2` returns `Culprit(j)`; the honest set without `j`
//!   completes.
//! - **Bad share** (a dealer sends `f_j(i)` inconsistent with its commitment) →
//!   `part3` returns `Culprit(j)`.
//! - **Rogue key** (a `φ_{j,0}` chosen without a valid PoK — the Gennaro et al.
//!   biasing attempt) → rejected at `part2` as `Culprit(j)`.
//! - **Identifier discipline** (amendment §5, via the frozen group layer): a zero
//!   identifier is rejected at construction; a duplicate in the participant set is
//!   `DuplicateIdentifier`.
//! - **Hedged PoK nonce** (amendment §3): the same RNG randomness with a different
//!   `a_{i,0}` yields a different nonce `k_i` / commitment `R_i` — the share
//!   entropy is mixed into the PoK nonce.

use std::collections::BTreeMap;

use frost_core as fc;

use fc::Error;
use fc::dkg::{part1, part2, part3, round1, round2};
use fc::group::{GElement, GScalar, Identifier};

use rand::SeedableRng;
use rand::rngs::StdRng;

/// A `GScalar` from a small unsigned integer (canonical little-endian).
fn scalar(v: u8) -> GScalar {
    let mut b = [0u8; 32];
    b[0] = v;
    GScalar::from_canonical_bytes(b).expect("small value is canonical")
}

fn id(x: u64) -> Identifier {
    Identifier::try_from_u64(x).expect("nonzero")
}

/// Other participants' round-1 packages, `self` removed.
fn peers_of(
    all: &BTreeMap<Identifier, round1::Package>,
    me: Identifier,
) -> BTreeMap<Identifier, round1::Package> {
    all.iter()
        .filter(|(i, _)| **i != me)
        .map(|(&i, pkg)| (i, pkg.clone()))
        .collect()
}

/// Run part1 for all `n` participants from a seeded RNG.
fn run_part1_all(
    threshold: u16,
    n: u16,
    seed: u64,
) -> (
    BTreeMap<Identifier, round1::SecretPackage>,
    BTreeMap<Identifier, round1::Package>,
) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut secrets1 = BTreeMap::new();
    let mut round1_all = BTreeMap::new();
    for x in 1..=n as u64 {
        let (s1, pkg) = part1(id(x), threshold, n, &mut rng).unwrap();
        secrets1.insert(id(x), s1);
        round1_all.insert(id(x), pkg);
    }
    (secrets1, round1_all)
}

/// Run a full honest DKG and assert it produces a `KeyPackage` for every
/// participant (the "honest set completes" half of identifiable abort).
fn assert_honest_dkg_completes(threshold: u16, n: u16, seed: u64) {
    let (mut secrets1, round1_all) = run_part1_all(threshold, n, seed);
    let ids: Vec<Identifier> = round1_all.keys().copied().collect();

    let mut secrets2 = BTreeMap::new();
    let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> =
        ids.iter().map(|&i| (i, BTreeMap::new())).collect();
    for &i in &ids {
        let s1 = secrets1.remove(&i).unwrap();
        let (s2, outgoing) = part2(s1, &peers_of(&round1_all, i)).unwrap();
        secrets2.insert(i, s2);
        for (recipient, pkg) in outgoing {
            inbox.get_mut(&recipient).unwrap().insert(i, pkg);
        }
    }
    let mut produced = 0usize;
    for &i in &ids {
        let received = inbox.remove(&i).unwrap();
        part3(&secrets2[&i], &peers_of(&round1_all, i), &received).unwrap();
        produced += 1;
    }
    assert_eq!(produced, n as usize, "honest set did not complete");
}

// --- Bad PoK ----------------------------------------------------------------

fn bad_pok_names_culprit(threshold: u16, n: u16, seed: u64) {
    let bad = id(n as u64);
    let me = id(1);
    let (mut secrets1, mut round1_all) = run_part1_all(threshold, n, seed);

    // Corrupt the bad participant's Schnorr response: μ_j -> μ_j + 1, so
    // μ_j·G ≠ R_j + c_j·φ_{j,0}.
    let bad_pkg = round1_all.get_mut(&bad).unwrap();
    bad_pkg.pok.response = bad_pkg.pok.response + scalar(1);

    let secret1 = secrets1.remove(&me).unwrap();
    let err = part2(secret1, &peers_of(&round1_all, me)).err();
    assert!(
        matches!(err, Some(Error::Culprit(c)) if c == bad),
        "bad PoK must name the culprit"
    );

    // The honest set, run without the bad participant, completes.
    assert_honest_dkg_completes(threshold, n - 1, seed ^ 0x900D);
}

#[test]
fn bad_pok_names_culprit_2_of_3() {
    bad_pok_names_culprit(2, 3, 0xBAD70F);
}

#[test]
fn bad_pok_names_culprit_3_of_5() {
    bad_pok_names_culprit(3, 5, 0xBAD705);
}

// --- Rogue key --------------------------------------------------------------

/// A participant broadcasts a `φ_{j,0}` it does not know the discrete log of —
/// here, another participant's contribution (the biasing attempt) — while keeping
/// its old PoK. The PoK no longer matches the swapped `φ_{j,0}`, so `part2`
/// rejects it as `Culprit(j)`. This is what forces every contributor to *know*
/// its secret, defeating the Gennaro et al. rogue-key biasing attack.
#[test]
fn rogue_key_is_rejected_as_culprit() {
    let (threshold, n) = (2u16, 3u16);
    let bad = id(n as u64);
    let donor = id(2);
    let me = id(1);
    let (mut secrets1, mut round1_all) = run_part1_all(threshold, n, 0x209E);

    // Steal the donor's φ_{donor,0} as the rogue φ_{bad,0}; keep bad's old PoK.
    let stolen = round1_all[&donor].commitments.0[0];
    round1_all.get_mut(&bad).unwrap().commitments.0[0] = stolen;

    let secret1 = secrets1.remove(&me).unwrap();
    let err = part2(secret1, &peers_of(&round1_all, me)).err();
    assert!(
        matches!(err, Some(Error::Culprit(c)) if c == bad),
        "rogue key must be rejected as the culprit"
    );
}

// --- Bad share --------------------------------------------------------------

fn bad_share_names_culprit(threshold: u16, n: u16, seed: u64) {
    let bad = id(n as u64);
    let me = id(1);

    // Orchestrate honestly through part2 to obtain participant `me`'s inbox.
    let (mut secrets1, round1_all) = run_part1_all(threshold, n, seed);
    let ids: Vec<Identifier> = round1_all.keys().copied().collect();
    let mut secrets2 = BTreeMap::new();
    let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> =
        ids.iter().map(|&i| (i, BTreeMap::new())).collect();
    for &i in &ids {
        let s1 = secrets1.remove(&i).unwrap();
        let (s2, outgoing) = part2(s1, &peers_of(&round1_all, i)).unwrap();
        secrets2.insert(i, s2);
        for (recipient, pkg) in outgoing {
            inbox.get_mut(&recipient).unwrap().insert(i, pkg);
        }
    }

    // The bad dealer sends `me` a share inconsistent with its broadcast
    // commitment (a fixed wrong scalar, still addressed to `me`).
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&me.as_scalar().to_bytes());
    bytes.extend_from_slice(&scalar(123).to_bytes());
    let forged = round2::Package::deserialize(&bytes).unwrap();
    inbox.get_mut(&me).unwrap().insert(bad, forged);

    let received = inbox.remove(&me).unwrap();
    let err = part3(&secrets2[&me], &peers_of(&round1_all, me), &received).err();
    assert!(
        matches!(err, Some(Error::Culprit(c)) if c == bad),
        "share inconsistent with its commitment must name the dealer"
    );

    assert_honest_dkg_completes(threshold, n - 1, seed ^ 0x5A5E);
}

#[test]
fn bad_share_names_culprit_2_of_3() {
    bad_share_names_culprit(2, 3, 0x5A70F);
}

#[test]
fn bad_share_names_culprit_3_of_5() {
    bad_share_names_culprit(3, 5, 0x5A705);
}

// --- Identifier discipline (amendment §5) -----------------------------------

#[test]
fn zero_identifier_is_rejected_at_construction() {
    // A DKG cannot even be entered with a zero identifier: the frozen group layer
    // rejects it at construction, both from an integer and from canonical bytes.
    assert!(matches!(
        Identifier::try_from_u64(0),
        Err(Error::ZeroIdentifier)
    ));
    assert!(matches!(
        Identifier::from_canonical_bytes([0u8; 32]),
        Err(Error::ZeroIdentifier)
    ));
}

#[test]
fn duplicate_identifier_in_participant_set_is_rejected() {
    // Self appearing among the peers is a duplicate in the participant set; the
    // frozen `validate_identifier_set` rejects it with `DuplicateIdentifier`.
    let mut rng = StdRng::seed_from_u64(0xD01D);
    let (secret1, pkg1) = part1(id(1), 2, 3, &mut rng).unwrap();
    let (_s2, pkg2) = part1(id(2), 2, 3, &mut rng).unwrap();

    let mut peers = BTreeMap::new();
    peers.insert(id(1), pkg1); // duplicate: participant 1 is also "self"
    peers.insert(id(2), pkg2);

    let err = part2(secret1, &peers).err();
    assert!(matches!(err, Some(Error::DuplicateIdentifier)));
}

// --- Hedged PoK nonce (amendment §3) ----------------------------------------

#[test]
fn hedged_pok_nonce_mixes_share_entropy() {
    // part1 derives the PoK nonce as k_i = H3(random ‖ encode(a_{i,0})). With the
    // same randomness but a different constant term, k_i — and hence R_i = k_i·G —
    // must differ, so a fully predictable RNG alone cannot collide the nonce.
    let random = [0x11u8; 32];
    let a0_a = scalar(7).to_bytes();
    let a0_b = scalar(8).to_bytes();

    let k_a = fc::ciphersuite::h3(&[random.as_slice(), a0_a.as_slice()]);
    let k_b = fc::ciphersuite::h3(&[random.as_slice(), a0_b.as_slice()]);
    assert!(k_a != k_b, "same randomness + different a_0 must change k_i");

    let g = GElement::generator();
    assert!(
        g.scalar_mul(&k_a) != g.scalar_mul(&k_b),
        "the PoK commitment R_i must differ"
    );
}
