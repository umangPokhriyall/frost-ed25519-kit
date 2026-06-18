//! ROS resistance: the same polynomial-time solver, two oracles, two verdicts
//! (phase3-spec §3.4, kickoff-amendment-1 §1).
//!
//! [`legacy::ros_attack`] is the Benhamouda–Lefranc–Loss–Orsini–Raykova (2020)
//! polynomial-time ROS forger. This file runs it twice:
//!
//! - **Positive control** ([`ros_forges_the_legacy_oracle`]): against the archived
//!   naive single-key Schnorr oracle it produces `(R*, z*)` that verifies under the
//!   standard equation on a message no session signed — the headline forgery, also
//!   committed as `legacy/results/ros_forgery.txt`.
//! - **Negative control** ([`frost_denies_the_ros_solver`]): against a thin
//!   [`SchnorrLikeOracle`] adapter over the frozen FROST `commit`/`sign` path it
//!   returns [`RosOutcome::NoSolution`] — *structurally*, not as a failed-attempt
//!   count.
//!
//! # Why FROST denies the solver — the binding-factor argument
//!
//! The ROS attack needs every session to be a **homomorphic Schnorr response**:
//! a commitment `R_i = r_i·G` fixed at session-open time, and a response
//! `z_i = r_i + c_i·s` whose challenge `c_i = H(R_i ‖ X ‖ m)` is a function of the
//! pair `(R_i, m)` **alone**. Only then can the solver, after seeing all the
//! `R_i`, pre-commit to coefficients `a_i`, fix `R* = Σ a_i·R_i` and the constant
//! `K = Σ a_i·c_i^0`, and then choose each session's message so that
//! `Σ a_i·c_i = c* = H(R* ‖ X ‖ m*)`. That linear system in the per-session
//! challenges is the attack.
//!
//! FROST destroys the precondition. A signer's round-1 output is a **pair** of
//! commitments `(D_i, E_i)`, and its effective per-session commitment is
//!
//! ```text
//!   R_i^eff = D_i + ρ_i·E_i ,   ρ_i = H1(group_public ‖ H4(msg) ‖ H5(commitment_list) ‖ id) .
//! ```
//!
//! The binding factor `ρ_i` is a hash of the **message** and the **full commitment
//! list**. So:
//!
//! 1. `R_i^eff` is not fixed at open time — it slides with the message the solver
//!    has not yet chosen. The solver can pin only some fixed `R_i` (here `D_i`),
//!    which is *not* the commitment the response actually uses.
//! 2. The response is `z_i = d_i + ρ_i·e_i + λ_i·c·s_i`, i.e.
//!    `z_i·G = R_i^eff + c·X`, with `c = H2(R^eff ‖ X ‖ msg)`. There is **no**
//!    scalar `c_i = f(R_i, msg)` for which `z_i·G == R_i + c_i·X` with a *fixed*
//!    `R_i` — because `R_i^eff − R_i = ρ_i·E_i` is itself a message-dependent point.
//!
//! Therefore the per-session challenge is not determined until the messages are
//! fixed, and the moment the messages are fixed the commitments `R_i^eff` (hence
//! `R*` and `c*`) move with them — the system is never the fixed linear system the
//! solver can solve. The solver detects this concretely: closing the first session
//! and checking the homomorphic-Schnorr invariant `z_i·G == R_i + challenge(R_i,
//! msg)·X` fails, so it returns [`RosOutcome::NoSolution`]. The unsolvability is
//! structural; it does not depend on how many messages are tried.
//!
//! This is the same mechanism that defeats cross-session replay (Phase 3 §4): a
//! partial is bound to its exact `(msg, commitment-set)` by `ρ_i`, so it neither
//! transplants to another session nor composes into a forgery.

use std::collections::HashMap;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;

use frost_core::group::Identifier;
use frost_core::secret::{SigningNonces, SigningShare};
use frost_core::sign::{SigningCommitments, commit, sign as frost_sign};
use frost_core::{PublicKeyPackage, trusted_dealer_keygen};

use legacy::ros::schnorr_challenge;
use legacy::{NaiveSchnorrOracle, RosOutcome, SchnorrLikeOracle, ros_attack};

/// `ℓ = 256` per kickoff-amendment-1 §1.
const ELL: usize = 256;

/// Positive control: the solver forges the naive scheme the repo used to ship.
#[test]
fn ros_forges_the_legacy_oracle() {
    let mut oracle = NaiveSchnorrOracle::new(OsRng);
    let x = oracle.public_key();
    let target = b"ros_resistance positive forge: never honestly signed".to_vec();

    match ros_attack(&mut oracle, ELL, &target) {
        RosOutcome::Forged { sig, m_star, signed_messages, sessions, .. } => {
            // (1) verifies under the standard equation (legacy::verify is the
            //     cofactor-free `z·G == R + H(R ‖ X ‖ m)·X`).
            assert!(
                legacy::verify(&x, &m_star, &sig.commitment, &sig.response),
                "forged (R*, z*) must verify under the standard equation"
            );
            // (2) m* is provably outside the signed set.
            assert!(
                !signed_messages.contains(&m_star),
                "m* must be outside the signed set"
            );
            assert_eq!(sessions, ELL);
        }
        RosOutcome::NoSolution => panic!("the solver must forge the homomorphic legacy oracle"),
    }
}

/// Negative control: the same solver against FROST returns `NoSolution`.
#[test]
fn frost_denies_the_ros_solver() {
    let mut oracle = FrostSingleSignerOracle::new();
    let target = b"ros_resistance: FROST must refuse this message".to_vec();

    // Structural verdict — NOT "no verifying forgery in N tries". See the module
    // doc-comment for why the linear system the solver needs does not exist.
    assert!(
        matches!(ros_attack(&mut oracle, ELL, &target), RosOutcome::NoSolution),
        "FROST's binding factor must deny the solver its linear system"
    );
}

/// A 1-of-1 FROST signer presented to the solver through the [`SchnorrLikeOracle`]
/// surface, driving the frozen `commit`/`sign` path unchanged. It hands the solver
/// a *fixed* commitment (the hiding `D_i`) at open time and the genuine FROST
/// partial at sign time; the gap between them — the binding term `ρ_i·E_i` — is
/// exactly what defeats the attack.
struct FrostSingleSignerOracle {
    id: Identifier,
    share: SigningShare,
    public: PublicKeyPackage,
    group_public: EdwardsPoint,
    rng: OsRng,
    sessions: HashMap<u64, (SigningNonces, SigningCommitments)>,
    next: u64,
}

impl FrostSingleSignerOracle {
    fn new() -> Self {
        let mut rng = OsRng;
        let id = Identifier::try_from_u64(1).unwrap();
        let (mut key_packages, public) =
            trusted_dealer_keygen(1, &[id], &mut rng).expect("1-of-1 keygen");
        let share = key_packages.remove(&id).expect("our key package").signing_share;
        let group_public = decompress(&public.group_public.to_compressed());
        Self { id, share, public, group_public, rng, sessions: HashMap::new(), next: 0 }
    }
}

impl SchnorrLikeOracle for FrostSingleSignerOracle {
    type Session = u64;

    fn public_key(&self) -> EdwardsPoint {
        self.group_public
    }

    fn open_session(&mut self) -> (u64, EdwardsPoint) {
        let (nonces, commitments) = commit(self.id, &self.share, &mut self.rng);
        // The solver's view of "R_i": the hiding commitment D_i. It is fixed now,
        // but the response will use the message-dependent D_i + ρ_i·E_i.
        let d_i = decompress(&commitments.hiding.to_compressed());
        let sid = self.next;
        self.next += 1;
        self.sessions.insert(sid, (nonces, commitments));
        (sid, d_i)
    }

    fn challenge(&self, r_i: &EdwardsPoint, msg: &[u8]) -> Scalar {
        // The solver models FROST as plain Schnorr: c = H(R_i ‖ Y ‖ msg) — the very
        // challenge that forges the legacy oracle. The binding factor makes this
        // prediction wrong, which is the point of the negative control.
        schnorr_challenge(&r_i.compress(), &self.group_public.compress(), msg)
    }

    fn sign(&mut self, session: u64, msg: &[u8]) -> Scalar {
        let (nonces, commitments) = self.sessions.remove(&session).expect("open session");
        let list = [commitments];
        let share = frost_sign(&self.share, nonces, self.id, &list, &self.public, msg)
            .expect("1-of-1 FROST sign");
        // SignatureShare.z is a GScalar (canonical); lift to a dalek Scalar.
        Option::<Scalar>::from(Scalar::from_canonical_bytes(share.z.to_bytes()))
            .expect("partial signature scalar is canonical")
    }
}

/// Decompress a canonical 32-byte compressed point. All inputs here are produced
/// by the frozen group layer, so they always decompress.
fn decompress(bytes: &[u8; 32]) -> EdwardsPoint {
    CompressedEdwardsY(*bytes)
        .decompress()
        .expect("group-layer point decompresses")
}
