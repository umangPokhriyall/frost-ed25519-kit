//! Identifiable abort (phase1-spec §7.3, kickoff-amendment-1 §2).
//!
//! A bad partial must yield `Culprit(id)` naming the misbehaving signer, the
//! honest set must be unaffected, and `verify_share` must accept every honest
//! partial. Proven for 2-of-3 and 3-of-5. Two failure modes are covered:
//! a garbage `z_j`, and a partial computed against the WRONG cosigner set (wrong
//! Lagrange coefficient / binding factors), which the aggregator catches when it
//! re-derives the per-partial check against its own set.

use std::collections::BTreeMap;

use frost_core::error::Error;
use frost_core::group::{GScalar, Identifier};
use frost_core::keygen::{KeyPackage, PublicKeyPackage, trusted_dealer_keygen};
use frost_core::secret::SigningNonces;
use frost_core::sign::{SignatureShare, SigningCommitments, aggregate, commit, sign};
use frost_core::verify::verify_share;
use rand::rngs::OsRng;

// label -> (single-use nonces, public commitment) for one committed signer.
type Parts = BTreeMap<u64, (SigningNonces, SigningCommitments)>;
// keygen output: key packages, public package, and the committed nonce/commitment map.
type Setup = (BTreeMap<Identifier, KeyPackage>, PublicKeyPackage, Parts);

fn id(label: u64) -> Identifier {
    Identifier::try_from_u64(label).unwrap()
}

fn all_ids(n: u64) -> Vec<Identifier> {
    (1..=n).map(id).collect()
}

fn one() -> GScalar {
    let mut b = [0u8; 32];
    b[0] = 1;
    GScalar::from_canonical_bytes(b).unwrap()
}

// keygen + per-signer commit for `signer_labels`; returns the key packages, the
// public package, and a map label -> (nonces, commitments) so each test can drive
// `sign` over whatever cosigner set it wants.
fn setup(t: u16, n: u64, signer_labels: &[u64]) -> Setup {
    let mut rng = OsRng;
    let (kps, public) = trusted_dealer_keygen(t, &all_ids(n), &mut rng).unwrap();
    let mut parts = BTreeMap::new();
    for &label in signer_labels {
        let (nonces, com) = commit(id(label), &kps[&id(label)].signing_share, &mut rng);
        parts.insert(label, (nonces, com));
    }
    (kps, public, parts)
}

fn commitments_of(parts: &Parts, labels: &[u64]) -> Vec<SigningCommitments> {
    labels.iter().map(|l| parts[l].1.clone()).collect()
}

// Consume `label`'s single-use nonces, signing over the cosigner set `set`.
fn sign_one(
    kps: &BTreeMap<Identifier, KeyPackage>,
    public: &PublicKeyPackage,
    parts: &mut Parts,
    label: u64,
    set: &[SigningCommitments],
    msg: &[u8],
) -> SignatureShare {
    let (nonces, _com) = parts.remove(&label).unwrap();
    sign(&kps[&id(label)].signing_share, nonces, id(label), set, public, msg).unwrap()
}

fn garbage_partial_case(t: u16, n: u64, labels: &[u64], bad: u64) {
    let msg = b"identifiable abort: garbage partial";
    let (kps, public, mut parts) = setup(t, n, labels);
    let set = commitments_of(&parts, labels);

    let mut shares: Vec<SignatureShare> = labels
        .iter()
        .map(|&l| sign_one(&kps, &public, &mut parts, l, &set, msg))
        .collect();

    // The honest set aggregates and verifies.
    assert!(aggregate(&shares, &set, &public, msg).is_ok());

    // Garble one signer's partial; aggregate must name exactly that signer.
    for s in &mut shares {
        if s.id == id(bad) {
            s.z = s.z + one();
        }
    }
    assert!(
        matches!(aggregate(&shares, &set, &public, msg), Err(Error::Culprit(c)) if c == id(bad)),
        "expected Culprit({bad}) from a garbage partial"
    );
}

#[test]
fn garbage_partial_yields_culprit_2_of_3() {
    garbage_partial_case(2, 3, &[1, 2], 2);
}

#[test]
fn garbage_partial_yields_culprit_3_of_5() {
    garbage_partial_case(3, 5, &[1, 2, 3], 3);
}

/// A signer computes its partial against the wrong cosigner set (so a wrong
/// Lagrange coefficient and wrong binding factors / challenge): the aggregator,
/// re-deriving the check over its own set, names it as the culprit. 3-of-5:
/// aggregator set A = {1,2,3}; signer 3 mistakenly signs over B = {1,3,4}.
#[test]
fn wrong_cosigner_set_partial_yields_culprit_3_of_5() {
    let msg = b"identifiable abort: wrong lambda";
    let (kps, public, mut parts) = setup(3, 5, &[1, 2, 3, 4]);
    let set_a = commitments_of(&parts, &[1, 2, 3]);
    let set_b = commitments_of(&parts, &[1, 3, 4]);

    let s1 = sign_one(&kps, &public, &mut parts, 1, &set_a, msg);
    let s2 = sign_one(&kps, &public, &mut parts, 2, &set_a, msg);
    // Signer 3's own commitment is identical in A and B (one commit), but it
    // derived z_3 with the {1,3,4} factors instead of {1,2,3}.
    let s3 = sign_one(&kps, &public, &mut parts, 3, &set_b, msg);

    let shares = vec![s1, s2, s3];
    assert!(
        matches!(aggregate(&shares, &set_a, &public, msg), Err(Error::Culprit(c)) if c == id(3)),
        "expected Culprit(3) from a wrong-cosigner-set partial"
    );
}

#[test]
fn verify_share_accepts_every_honest_partial() {
    for (t, n, labels) in [(2u16, 3u64, vec![1u64, 2]), (3, 5, vec![1, 2, 3])] {
        let msg = b"identifiable abort: honest partials";
        let (kps, public, mut parts) = setup(t, n, &labels);
        let set = commitments_of(&parts, &labels);
        for &label in &labels {
            let share = sign_one(&kps, &public, &mut parts, label, &set, msg);
            assert!(
                verify_share(&share, &set, &public, msg).is_ok(),
                "verify_share rejected an honest partial for signer {label}"
            );
        }
    }
}
