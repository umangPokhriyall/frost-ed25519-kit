//! Consolidated adversarial audit — the single threat-surface index (phase3-spec §4).
//!
//! # Overlap with earlier suites (documented, not accidental)
//!
//! Phases 0–2 each prove their own invariants in their own suites; this file is a
//! defense-in-depth re-exercise of the cross-cutting ones in **one** place a
//! reviewer can read as the threat index, plus the genuinely new Phase 3 cases.
//! Primary ownership:
//!
//! - **Non-canonical scalar / non-prime-order point rejection** — owned by the
//!   group layer (`group.rs`) and `tests/identifiers.rs`. Re-exercised below as
//!   named malformed-bytes regressions.
//! - **Zero / duplicate identifier rejection** — owned by `tests/identifiers.rs`
//!   (amendment §5). Re-exercised below.
//! - **Bad partial → `Culprit`** — owned by `tests/identifiable_abort.rs`
//!   (amendment §2). Re-exercised here through the wrong-cosigner-set case.
//! - **Bad DKG PoK / share / rogue-key → `Culprit`** — owned by
//!   `tests/dkg_adversarial.rs`. Not duplicated here (DKG-internal).
//!
//! New here (Phase 3):
//! - **Cross-session replay rejection** — a partial valid in session A is rejected
//!   in session B. This is the anti-replay face of the binding factor: the same
//!   `ρ_i = H1(group_public ‖ H4(msg) ‖ H5(commitment_list) ‖ id)` that denies the
//!   ROS solver its linear system (`tests/ros_resistance.rs`) binds every partial
//!   to its exact `(msg, commitment-set)`, so it neither transplants to another
//!   session nor composes into a forgery.
//! - **Consolidated malformed-bytes regressions** — a few named inputs per public
//!   deserializer (`tests/../fuzz/` is the exhaustive version); each returns `Err`,
//!   never panics.
//! - **Nonce single-use** — a compile-time guarantee, documented below; not a
//!   runtime check.

use frost_core::dkg::round2;
use frost_core::group::{GElement, GScalar, Identifier};
use frost_core::secret::SigningShare;
use frost_core::sign::{
    Signature, SignatureShare, SigningCommitments, aggregate, commit, sign as frost_sign,
};
use frost_core::verify::verify_share;
use frost_core::{Error, KeyPackage, PublicKeyPackage, trusted_dealer_keygen};

use rand::rngs::OsRng;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run one full FROST signing session for `signer_ids` over `msg`, returning the
/// commitment set and the verified partials. Keygen is shared by the caller so two
/// sessions belong to the same group (the precondition for a replay test).
fn sign_session(
    key_packages: &BTreeMap<Identifier, KeyPackage>,
    public: &PublicKeyPackage,
    signer_ids: &[Identifier],
    msg: &[u8],
) -> (Vec<SigningCommitments>, Vec<SignatureShare>) {
    let mut rng = OsRng;
    let mut commitments = Vec::new();
    let mut nonces = Vec::new();
    for &id in signer_ids {
        let kp = &key_packages[&id];
        let (n, c) = commit(id, &kp.signing_share, &mut rng);
        commitments.push(c);
        nonces.push(n);
    }
    let mut shares = Vec::new();
    for (&id, n) in signer_ids.iter().zip(nonces) {
        let kp = &key_packages[&id];
        shares.push(frost_sign(&kp.signing_share, n, id, &commitments, public, msg).unwrap());
    }
    (commitments, shares)
}

fn ids(values: &[u64]) -> Vec<Identifier> {
    values.iter().map(|&v| Identifier::try_from_u64(v).unwrap()).collect()
}

// ---------------------------------------------------------------------------
// Cross-session replay (the new Phase 3 case)
// ---------------------------------------------------------------------------

/// A `SignatureShare` valid in session A is rejected when replayed into session B
/// (different message, different cosigner set). The binding factor and challenge
/// recomputed in B bind to B's `(msg, commitment-set)`, so A's partial does not
/// verify there — `verify_share` returns `Culprit(id)`. Demonstrates the binding
/// factor's anti-replay property (phase3-spec §4).
#[test]
fn cross_session_replay_is_rejected() {
    let mut rng = OsRng;
    let all = ids(&[1, 2, 3]);
    let (key_packages, public) = trusted_dealer_keygen(2, &all, &mut rng).unwrap();

    // Session A: signers {1, 2}, message A.
    let a_signers = ids(&[1, 2]);
    let msg_a = b"session A: authorize transfer #1";
    let (commitments_a, shares_a) = sign_session(&key_packages, &public, &a_signers, msg_a);

    // Session B: signers {1, 3}, message B — same group, different everything else.
    let b_signers = ids(&[1, 3]);
    let msg_b = b"session B: authorize transfer #2";
    let (commitments_b, shares_b) = sign_session(&key_packages, &public, &b_signers, msg_b);

    let id1 = Identifier::try_from_u64(1).unwrap();
    let share_a1 = shares_a.iter().find(|s| s.id == id1).unwrap().clone();

    // Baseline: the partial IS valid in its own session A.
    assert!(
        verify_share(&share_a1, &commitments_a, &public, msg_a).is_ok(),
        "signer 1's partial must verify in its own session"
    );

    // Replay into session B's context → rejected as Culprit(1).
    assert!(
        matches!(
            verify_share(&share_a1, &commitments_b, &public, msg_b),
            Err(Error::Culprit(id)) if id == id1
        ),
        "A's partial must be rejected when replayed into session B"
    );

    // And replaying it through `aggregate` (swapping it in for B's real partial
    // from signer 1) also names the culprit — only verified partials are summed.
    let mut spliced = shares_b.clone();
    for s in &mut spliced {
        if s.id == id1 {
            *s = share_a1.clone();
        }
    }
    assert!(
        matches!(
            aggregate(&spliced, &commitments_b, &public, msg_b),
            Err(Error::Culprit(id)) if id == id1
        ),
        "aggregate must reject a replayed partial as Culprit(1)"
    );

    // The genuine session B (unspliced) still aggregates and verifies.
    assert!(aggregate(&shares_b, &commitments_b, &public, msg_b).is_ok());
}

/// Narrower face of the same property: a partial computed for cosigner set {1, 2}
/// is rejected against a {1, 3} commitment set even on the *same* message, because
/// the Lagrange coefficient and binding factor differ. Re-exercises the
/// identifiable-abort `Culprit` path (owned by `tests/identifiable_abort.rs`)
/// through a wrong-cosigner-set partial.
#[test]
fn wrong_cosigner_set_partial_is_culprit() {
    let mut rng = OsRng;
    let all = ids(&[1, 2, 3]);
    let (key_packages, public) = trusted_dealer_keygen(2, &all, &mut rng).unwrap();
    let msg = b"same message, different cosigner set";

    let (commitments_12, shares_12) = sign_session(&key_packages, &public, &ids(&[1, 2]), msg);
    let (commitments_13, _shares_13) = sign_session(&key_packages, &public, &ids(&[1, 3]), msg);

    let id1 = Identifier::try_from_u64(1).unwrap();
    let share_12_id1 = shares_12.iter().find(|s| s.id == id1).unwrap().clone();

    // Valid against its own {1,2} set; Culprit against the {1,3} set.
    assert!(verify_share(&share_12_id1, &commitments_12, &public, msg).is_ok());
    assert!(matches!(
        verify_share(&share_12_id1, &commitments_13, &public, msg),
        Err(Error::Culprit(id)) if id == id1
    ));
}

// ---------------------------------------------------------------------------
// Named malformed-bytes regressions (one cluster per public deserializer)
//
// Every public `from_bytes`/deserialize must return `Err`, never panic, on these
// inputs. The fuzz crate (`fuzz/`) is the exhaustive version; these pin specific
// regressions. NOTE: `SigningCommitments`, `SignatureShare`, and `round1::Package`
// have public *fields* but no byte-level deserializer in the frozen API
// (`message.rs` was never introduced), so there is no `from_bytes` to malform for
// them; their wire-relevant components (compressed points, canonical scalars) are
// covered by the `GElement`/`GScalar`/`Identifier` clusters below.
// ---------------------------------------------------------------------------

/// The little-endian encoding of the group order `L`. `L` is the smallest
/// non-canonical scalar: `from_canonical_bytes(L)` must reject (never reduce).
const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A known order-8 (non-prime-order) point of edwards25519. It decompresses, but
/// is not torsion-free, so `GElement::from_compressed` must reject it as
/// `NonPrimeOrderPoint` — the small-subgroup / cofactor-8 guard.
const ORDER_8_POINT: [u8; 32] = [
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
];

#[test]
fn gscalar_rejects_non_canonical_bytes() {
    // L and all-0xFF are both >= L → non-canonical, rejected, no coercion.
    assert!(matches!(
        GScalar::from_canonical_bytes(L_BYTES),
        Err(Error::NonCanonicalScalar)
    ));
    assert!(matches!(
        GScalar::from_canonical_bytes([0xff; 32]),
        Err(Error::NonCanonicalScalar)
    ));
}

#[test]
fn gelement_rejects_bad_and_non_prime_order_points() {
    // y = 2 has no valid x on the curve → InvalidPointEncoding (does not decode).
    let mut y2 = [0u8; 32];
    y2[0] = 2;
    assert!(matches!(
        GElement::from_compressed(y2),
        Err(Error::InvalidPointEncoding)
    ));
    // A decodable but order-8 point → NonPrimeOrderPoint (cofactor guard).
    assert!(matches!(
        GElement::from_compressed(ORDER_8_POINT),
        Err(Error::NonPrimeOrderPoint)
    ));
    // All-0xFF decodes to a non-torsion-free point → NonPrimeOrderPoint, also
    // rejected (it is not InvalidPointEncoding — the cofactor guard is what stops it).
    assert!(matches!(
        GElement::from_compressed([0xff; 32]),
        Err(Error::NonPrimeOrderPoint)
    ));
}

#[test]
fn identifier_rejects_zero_and_non_canonical() {
    assert!(matches!(
        Identifier::from_canonical_bytes([0u8; 32]),
        Err(Error::ZeroIdentifier)
    ));
    assert!(matches!(
        Identifier::from_canonical_bytes(L_BYTES),
        Err(Error::NonCanonicalScalar)
    ));
}

#[test]
fn signing_share_rejects_non_canonical() {
    assert!(matches!(
        SigningShare::from_canonical_bytes(L_BYTES),
        Err(Error::NonCanonicalScalar)
    ));
}

#[test]
fn signature_rejects_malformed_r_and_z() {
    // Bad R (non-prime-order), good z (zero is canonical).
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&ORDER_8_POINT);
    assert!(matches!(Signature::from_bytes(b), Err(Error::NonPrimeOrderPoint)));

    // Good R (the identity, torsion-free), bad z (= L, non-canonical).
    let mut b = [0u8; 64];
    b[0] = 1; // compressed identity: y = 1, sign 0
    b[32..].copy_from_slice(&L_BYTES);
    assert!(matches!(Signature::from_bytes(b), Err(Error::NonCanonicalScalar)));
}

#[test]
fn round2_package_rejects_bad_length_and_fields() {
    // Wrong length → InvalidEncoding (never indexes out of bounds / panics).
    assert!(matches!(
        round2::Package::deserialize(&[0u8; 63]),
        Err(Error::InvalidEncoding(_))
    ));
    assert!(matches!(
        round2::Package::deserialize(&[]),
        Err(Error::InvalidEncoding(_))
    ));

    // 64 bytes, zero recipient identifier → ZeroIdentifier.
    let mut b = [0u8; 64];
    b[32] = 1; // a canonical, nonzero share so only the recipient is at fault
    assert!(matches!(
        round2::Package::deserialize(&b),
        Err(Error::ZeroIdentifier)
    ));

    // 64 bytes, valid recipient, non-canonical share scalar → NonCanonicalScalar.
    let mut b = [0u8; 64];
    b[0] = 1; // recipient id = 1
    b[32..].copy_from_slice(&L_BYTES);
    assert!(matches!(
        round2::Package::deserialize(&b),
        Err(Error::NonCanonicalScalar)
    ));
}

// ---------------------------------------------------------------------------
// Nonce single-use — a compile-time guarantee (phase3-spec §4)
// ---------------------------------------------------------------------------

/// `SigningNonces` is consumed by value by `sign` and implements neither `Clone`
/// nor `Copy`, so reuse is a *compile* error, not a runtime check we could weaken
/// the type to exercise. The snippet below does **not** compile — the second
/// `frost_sign` call is a use-after-move (this is a documented compile-fail, not an
/// executed doctest: integration-test files carry no runnable doctests):
///
/// ```ignore
/// let (nonces, commitments) = commit(id, &kp.signing_share, &mut rng);
/// let list = [commitments];
/// let _a = frost_sign(&kp.signing_share, nonces, id, &list, &public, b"m1").unwrap();
/// // ERROR[E0382]: `nonces` was moved into the call above; using it again is
/// // rejected by the borrow checker — single use is enforced by the type.
/// let _b = frost_sign(&kp.signing_share, nonces, id, &list, &public, b"m2").unwrap();
/// ```
///
/// The runtime body here only confirms the public path *consumes* the nonces; the
/// no-reuse property itself is the borrow-check above, plus the absence of
/// `Clone`/`Copy` on `SigningNonces` in the frozen `secret.rs`.
#[test]
fn nonce_single_use_is_a_compile_time_guarantee() {
    let mut rng = OsRng;
    let id = Identifier::try_from_u64(1).unwrap();
    let (kps, public) = trusted_dealer_keygen(1, &[id], &mut rng).unwrap();
    let kp = &kps[&id];
    let (nonces, commitments) = commit(id, &kp.signing_share, &mut rng);
    let list = [commitments];
    // `nonces` is moved here; the compile-fail snippet in the doc-comment shows a
    // second use would not compile. We cannot assert that at runtime without
    // weakening the type, which would defeat the property.
    let _ = frost_sign(&kp.signing_share, nonces, id, &list, &public, b"m1").unwrap();
}
