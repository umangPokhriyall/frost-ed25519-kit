//! Differential test: hand-rolled `frost-core` vs the `frost-ed25519` oracle
//! (phase1-spec §7.2).
//!
//! ≥10,000 randomized cases over `2 ≤ t ≤ n ≤ 8`, a random signer subset of size
//! ≥ t, a random message, and a random seed. `frost-ed25519`'s trusted-dealer
//! keygen is the single source of keys (imported into `frost-core`), and both
//! libraries are driven from identically seeded RNGs. Because both use the same
//! hedged nonce construction `H3(random ‖ encode(share))` and draw the hiding
//! then binding randomness in the same order, the nonces coincide and the
//! signatures must match byte-for-byte. For each case we assert:
//!
//! - identical group public key,
//! - identical per-signer commitments and partials (localization),
//! - identical aggregate signature bytes,
//! - the `frost-core` signature verifies under `frost-ed25519`'s verifier and
//!   vice versa (identical accept decisions).
//!
//! Any divergence is a STOP.

use std::collections::BTreeMap;

use frost_core as fc;
use frost_ed25519 as ed;

use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn to32(v: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(v);
    a
}

fn to64(v: &[u8]) -> [u8; 64] {
    let mut a = [0u8; 64];
    a.copy_from_slice(v);
    a
}

// A per-signer seed; two RNGs built from it yield the same byte stream, so the
// two libraries draw identical hedged-nonce randomness for that signer.
fn signer_seed(seed: u64, label: u16) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&seed.to_le_bytes());
    s[8..10].copy_from_slice(&label.to_le_bytes());
    s
}

fn run_case(n: u16, t: u16, signers: &[u16], msg: &[u8], seed: u64) -> Result<(), TestCaseError> {
    // --- Oracle keygen (frost-ed25519), with explicit identifiers 1..=n ---
    let ed_ids: Vec<ed::Identifier> =
        (1..=n).map(|i| ed::Identifier::try_from(i).unwrap()).collect();
    let mut keygen_rng = StdRng::seed_from_u64(seed ^ 0xA5A5_A5A5_5A5A_5A5A);
    let (ed_secret_shares, ed_pubkeys) = ed::keys::generate_with_dealer(
        n,
        t,
        ed::keys::IdentifierList::Custom(&ed_ids),
        &mut keygen_rng,
    )
    .unwrap();

    // ed KeyPackage per integer label; integer `lab` <-> ed_ids[lab-1].
    let mut ed_kps: BTreeMap<u16, ed::keys::KeyPackage> = BTreeMap::new();
    for lab in 1..=n {
        let ss = ed_secret_shares[&ed_ids[(lab - 1) as usize]].clone();
        ed_kps.insert(lab, ed::keys::KeyPackage::try_from(ss).unwrap());
    }

    // --- Import keys into frost-core ---
    let group_public =
        fc::group::GElement::from_compressed(to32(&ed_pubkeys.verifying_key().serialize().unwrap()))
            .unwrap();
    let mut fc_verifying_shares = BTreeMap::new();
    let mut fc_shares: BTreeMap<u16, fc::secret::SigningShare> = BTreeMap::new();
    for lab in 1..=n {
        let ed_id = ed_ids[(lab - 1) as usize];
        let x_i = fc::group::GElement::from_compressed(to32(
            &ed_pubkeys.verifying_shares()[&ed_id].serialize().unwrap(),
        ))
        .unwrap();
        fc_verifying_shares.insert(fc::group::Identifier::try_from_u64(lab as u64).unwrap(), x_i);
        let share =
            fc::secret::SigningShare::from_canonical_bytes(to32(&ed_kps[&lab].signing_share().serialize()))
                .unwrap();
        fc_shares.insert(lab, share);
    }
    let fc_public = fc::keygen::PublicKeyPackage {
        group_public,
        verifying_shares: fc_verifying_shares,
        threshold: t,
    };

    // group public must match the oracle's.
    prop_assert_eq!(
        group_public.to_compressed().to_vec(),
        ed_pubkeys.verifying_key().serialize().unwrap()
    );

    // --- Round 1: commit in both, from identically seeded RNGs ---
    let mut ed_commitments: BTreeMap<ed::Identifier, ed::round1::SigningCommitments> = BTreeMap::new();
    let mut ed_nonces: BTreeMap<u16, ed::round1::SigningNonces> = BTreeMap::new();
    let mut fc_commitments: Vec<fc::sign::SigningCommitments> = Vec::new();
    let mut fc_nonces: BTreeMap<u16, fc::secret::SigningNonces> = BTreeMap::new();

    for &lab in signers {
        let ed_id = ed_ids[(lab - 1) as usize];

        let mut rng_ed = StdRng::from_seed(signer_seed(seed, lab));
        let (ed_nonce, ed_com) = ed::round1::commit(ed_kps[&lab].signing_share(), &mut rng_ed);

        let mut rng_fc = StdRng::from_seed(signer_seed(seed, lab));
        let fc_id = fc::group::Identifier::try_from_u64(lab as u64).unwrap();
        let (fc_nonce, fc_com) = fc::sign::commit(fc_id, &fc_shares[&lab], &mut rng_fc);

        // Commitments must match (so the hedged nonces matched).
        prop_assert_eq!(fc_com.hiding.to_compressed().to_vec(), ed_com.hiding().serialize().unwrap());
        prop_assert_eq!(fc_com.binding.to_compressed().to_vec(), ed_com.binding().serialize().unwrap());

        ed_commitments.insert(ed_id, ed_com);
        ed_nonces.insert(lab, ed_nonce);
        fc_commitments.push(fc_com);
        fc_nonces.insert(lab, fc_nonce);
    }

    // --- Round 2: sign in both ---
    let ed_signing_package = ed::SigningPackage::new(ed_commitments, msg);
    let mut ed_sig_shares: BTreeMap<ed::Identifier, ed::round2::SignatureShare> = BTreeMap::new();
    let mut fc_sig_shares: Vec<fc::sign::SignatureShare> = Vec::new();

    for &lab in signers {
        let ed_id = ed_ids[(lab - 1) as usize];
        let ed_share = ed::round2::sign(&ed_signing_package, &ed_nonces[&lab], &ed_kps[&lab]).unwrap();

        let fc_id = fc::group::Identifier::try_from_u64(lab as u64).unwrap();
        let fc_nonce = fc_nonces.remove(&lab).unwrap();
        let fc_share =
            fc::sign::sign(&fc_shares[&lab], fc_nonce, fc_id, &fc_commitments, &fc_public, msg).unwrap();

        prop_assert_eq!(fc_share.z.to_bytes().to_vec(), ed_share.serialize());

        ed_sig_shares.insert(ed_id, ed_share);
        fc_sig_shares.push(fc_share);
    }

    // --- Aggregate in both; signatures must be byte-identical ---
    let ed_sig = ed::aggregate(&ed_signing_package, &ed_sig_shares, &ed_pubkeys).unwrap();
    let fc_sig = fc::sign::aggregate(&fc_sig_shares, &fc_commitments, &fc_public, msg).unwrap();

    let ed_sig_bytes = ed_sig.serialize().unwrap();
    let fc_sig_bytes = fc_sig.to_bytes().to_vec();
    prop_assert_eq!(&fc_sig_bytes, &ed_sig_bytes);

    // --- Cross-verify both directions (identical accept decisions) ---
    let ed_from_fc = ed::Signature::deserialize(&fc_sig_bytes).unwrap();
    prop_assert!(ed_pubkeys.verifying_key().verify(msg, &ed_from_fc).is_ok());

    let fc_from_ed = fc::sign::Signature::from_bytes(to64(&ed_sig_bytes)).unwrap();
    prop_assert!(fc::verify::verify(&fc_public.group_public, msg, &fc_from_ed).is_ok());

    Ok(())
}

// (n, t, signers, msg, seed) with 2 ≤ t ≤ n ≤ 8 and |signers| in t..=n.
fn case_strategy() -> impl Strategy<Value = (u16, u16, Vec<u16>, Vec<u8>, u64)> {
    (2u16..=8).prop_flat_map(|n| {
        (2u16..=n).prop_flat_map(move |t| {
            let pool: Vec<u16> = (1..=n).collect();
            (
                Just(n),
                Just(t),
                proptest::sample::subsequence(pool, (t as usize)..=(n as usize)),
                proptest::collection::vec(any::<u8>(), 0..48),
                any::<u64>(),
            )
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, max_shrink_iters: 64, .. ProptestConfig::default() })]

    /// Hand-rolled frost-core must agree with frost-ed25519 byte-for-byte across
    /// ≥10,000 randomized (t, n, subset, message, seed) cases.
    #[test]
    fn frost_core_matches_frost_ed25519((n, t, signers, msg, seed) in case_strategy()) {
        run_case(n, t, &signers, &msg, seed)?;
    }
}
