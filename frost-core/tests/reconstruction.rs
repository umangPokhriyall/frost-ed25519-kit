//! The Phase 0 green gate (phase0-spec §7). Reconstruction lives only in tests.
//!
//! Proves, at 2-of-3 and 3-of-5: any `t` signing shares Lagrange-interpolate to
//! a value whose `·G` is the group key; any `t-1` shares do not; Feldman
//! `verify_share` accepts honest shares and rejects a tampered one with
//! `InvalidShare`; and `verifying_share(id, commitments)` equals the
//! `KeyPackage` verifying share (the §2 derivation Phase 1 depends on).

use std::collections::BTreeMap;

use frost_core::error::Error;
use frost_core::group::{GElement, GScalar, Identifier};
use frost_core::keygen::trusted_dealer_keygen;
use frost_core::secret::SigningShare;
use frost_core::vss::{Commitments, verify_share, verifying_share};
use rand::rngs::OsRng;

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

/// Run trusted-dealer keygen and exercise the full §7 gate for `t`-of-`n`.
fn reconstruct_gate(threshold: u16, n: u64) {
    let t = threshold as usize;
    let ids: Vec<Identifier> = (1..=n)
        .map(|i| Identifier::try_from_u64(i).expect("nonzero"))
        .collect();
    let mut rng = OsRng;
    let (key_packages, pkp) =
        trusted_dealer_keygen(threshold, &ids, &mut rng).expect("valid keygen");

    assert_eq!(pkp.threshold, threshold);
    assert_eq!(pkp.verifying_shares.len(), ids.len());

    // (id, share scalar) for every participant.
    let shares: Vec<(Identifier, GScalar)> = ids
        .iter()
        .map(|id| (*id, key_packages[id].signing_share.to_scalar()))
        .collect();

    // Any t shares reconstruct a_0; (a_0)·G == group_public. Check two disjoint
    // t-subsets (the first t and the last t).
    for subset in [&shares[..t], &shares[(shares.len() - t)..]] {
        let a0 = interpolate_at_zero(subset);
        assert_eq!(
            GElement::generator().scalar_mul(&a0),
            pkp.group_public,
            "any {t} shares must reconstruct the group key"
        );
    }

    // Any t-1 shares interpolate to a value that does NOT yield the group key:
    // the secret is not determined by t-1 shares.
    let short = &shares[..(t - 1)];
    let w = interpolate_at_zero(short);
    assert_ne!(
        GElement::generator().scalar_mul(&w),
        pkp.group_public,
        "{} shares must not determine the group key",
        t - 1
    );

    // verifying_share equality + the X_i = s_i·G derivation, for every id.
    for id in &ids {
        let kp = &key_packages[id];
        assert_eq!(kp.verifying_share, pkp.verifying_shares[id]);
        assert_eq!(
            kp.verifying_share,
            GElement::generator().scalar_mul(&kp.signing_share.to_scalar()),
            "X_i must equal s_i·G"
        );
    }
}

#[test]
fn reconstruct_2_of_3() {
    reconstruct_gate(2, 3);
}

#[test]
fn reconstruct_3_of_5() {
    reconstruct_gate(3, 5);
}

/// Feldman `verify_share` accepts honest shares and rejects a tampered one with
/// `InvalidShare`, and `verifying_share(id, commitments) == s_i·G`. Built from
/// an explicit polynomial so the check is independent of keygen.
#[test]
fn feldman_verify_and_verifying_share() {
    // f(x) = 3 + 5·x (threshold 2), commitments C_0 = 3·G, C_1 = 5·G.
    let (a0, a1) = (scalar(3), scalar(5));
    let g = GElement::generator();
    let commitments = Commitments(vec![g.scalar_mul(&a0), g.scalar_mul(&a1)]);

    for idv in [1u64, 2, 3] {
        let id = Identifier::try_from_u64(idv).expect("nonzero");
        let x = id.as_scalar();
        let s = a0 + a1 * x;
        let share = SigningShare::from_canonical_bytes(s.to_bytes()).expect("canonical");

        // Honest share verifies, and its public image matches verifying_share.
        verify_share(id, &share, &commitments).expect("honest share verifies");
        assert_eq!(verifying_share(id, &commitments), g.scalar_mul(&s));

        // Tampered share (off by a_1) fails, naming the identifier.
        let tampered = SigningShare::from_canonical_bytes((s + a1).to_bytes()).expect("canonical");
        assert!(matches!(
            verify_share(id, &tampered, &commitments),
            Err(Error::InvalidShare(_))
        ));
    }
}

/// Threshold validation: zero threshold and threshold > participants are
/// rejected with `InvalidThreshold`.
#[test]
fn threshold_bounds_are_enforced() {
    let ids: Vec<Identifier> = (1..=3)
        .map(|i| Identifier::try_from_u64(i).expect("nonzero"))
        .collect();
    let mut rng = OsRng;

    assert!(matches!(
        trusted_dealer_keygen(0, &ids, &mut rng).map(|_| ()),
        Err(Error::InvalidThreshold)
    ));
    assert!(matches!(
        trusted_dealer_keygen(4, &ids, &mut rng).map(|_| ()),
        Err(Error::InvalidThreshold)
    ));
}

/// Sanity for the helper map type (keeps `BTreeMap` import honest if the test
/// shape changes): the dealer hands out exactly one package per identifier.
#[test]
fn one_package_per_identifier() {
    let ids: Vec<Identifier> = (1..=5)
        .map(|i| Identifier::try_from_u64(i).expect("nonzero"))
        .collect();
    let mut rng = OsRng;
    let (key_packages, _pkp): (BTreeMap<Identifier, _>, _) =
        trusted_dealer_keygen(3, &ids, &mut rng).expect("valid keygen");
    assert_eq!(key_packages.len(), ids.len());
    for id in &ids {
        assert_eq!(key_packages[id].id, *id);
    }
}
