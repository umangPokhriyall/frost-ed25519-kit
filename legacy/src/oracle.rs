//! The naive single-key Schnorr oracle (kickoff-amendment-1 §1, phase1-spec §8).
//!
//! # Reduction — why one key models the threshold scheme
//!
//! The legacy threshold aggregate is
//!
//! ```text
//!   z = Σ z_i = (Σ r_i) + c·(Σ λ_i s_i) = R + c·s
//! ```
//!
//! where `s` is the group secret, `R = Σ r_i·G`, `X = s·G`, and the challenge is
//! `c = H(R ‖ X ‖ msg)`. The Lagrange-weighted shares `λ_i s_i` sum to the single
//! group secret `s`, so the legacy threshold protocol **collapses to single-key
//! concurrent Schnorr**. This oracle models that single key directly; attacking
//! the full multi-party transcript would only obscure the result.
//!
//! There is **no binding factor** anywhere, and an **unlimited** number of
//! sessions may be open concurrently — exactly the structure the ROS forgery of
//! Benhamouda–Lefranc–Loss–Orsini–Raykova (2020) exploits. The polynomial-time
//! solver and `tests/ros_resistance.rs` are Phase 3; this phase only builds the
//! target and smoke-tests it. By contrast, `frost-core`'s binding factor
//! `ρ_i = H1(msg_hash ‖ commitment_list_hash ‖ identifier_i)` makes the per-session
//! challenge coefficients depend on the message and the full commitment list, so
//! the linear system the ROS solver needs never exists.

use std::collections::HashMap;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// Opaque handle to an open signing session.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(u64);

/// The naive single-key Schnorr signer. Holds the group secret `s` and `X = s·G`,
/// hands out fresh per-session commitments `R_i = r_i·G`, and signs any open
/// session with `z_i = r_i + H(R_i ‖ X ‖ msg)·s`. No binding factor, unlimited
/// concurrent open sessions — see the module docs for the reduction and why this
/// is the Phase 3 attack target.
pub struct NaiveSchnorrOracle<R> {
    rng: R,
    secret: Scalar,
    public: EdwardsPoint,
    next_id: u64,
    /// `session -> r_i`. Sessions are never evicted: the scheme offers no
    /// protection against concurrent or repeated queries (that is the point).
    sessions: HashMap<SessionId, Scalar>,
}

impl<R: RngCore + CryptoRng> NaiveSchnorrOracle<R> {
    /// Create an oracle with a fresh random group secret `s` and `X = s·G`.
    pub fn new(mut rng: R) -> Self {
        let secret = Scalar::random(&mut rng);
        let public = ED25519_BASEPOINT_POINT * secret;
        Self {
            rng,
            secret,
            public,
            next_id: 0,
            sessions: HashMap::new(),
        }
    }

    /// The group public key `X = s·G`.
    pub fn public_key(&self) -> EdwardsPoint {
        self.public
    }

    /// Open a session: sample a fresh nonce `r_i` and return its commitment
    /// `R_i = r_i·G`. Any number of sessions may be open at once.
    pub fn open_session(&mut self) -> (SessionId, CompressedEdwardsY) {
        let r = Scalar::random(&mut self.rng);
        let commitment = (ED25519_BASEPOINT_POINT * r).compress();
        let id = SessionId(self.next_id);
        self.next_id += 1;
        self.sessions.insert(id, r);
        (id, commitment)
    }

    /// Sign `msg` under an open session: `z_i = r_i + H(R_i ‖ X ‖ msg)·s`.
    ///
    /// Panics if `session` was never opened — this is an in-process attack
    /// harness driven by trusted Phase 3 code, not a peer-facing API.
    pub fn sign(&mut self, session: SessionId, msg: &[u8]) -> Scalar {
        let r = *self.sessions.get(&session).expect("unknown session id");
        let commitment = (ED25519_BASEPOINT_POINT * r).compress();
        let c = challenge(&commitment, &self.public.compress(), msg);
        r + c * self.secret
    }
}

/// Verify a naive Schnorr signature `(R, z)` on `msg` under `public`:
/// `z·G == R + H(R ‖ X ‖ msg)·X`. Returns `false` if `R` does not decompress.
pub fn verify(public: &EdwardsPoint, msg: &[u8], commitment: &CompressedEdwardsY, z: &Scalar) -> bool {
    let big_r = match commitment.decompress() {
        Some(p) => p,
        None => return false,
    };
    let c = challenge(commitment, &public.compress(), msg);
    ED25519_BASEPOINT_POINT * z == big_r + *public * c
}

/// `c = H(R ‖ X ‖ msg)` over SHA-512, reduced mod the group order (wide).
fn challenge(commitment: &CompressedEdwardsY, public: &CompressedEdwardsY, msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(commitment.as_bytes());
    h.update(public.as_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn one_session_signs_and_verifies() {
        let mut oracle = NaiveSchnorrOracle::new(OsRng);
        let x = oracle.public_key();
        let msg = b"legacy naive schnorr smoke";

        let (session, commitment) = oracle.open_session();
        let z = oracle.sign(session, msg);

        assert!(verify(&x, msg, &commitment, &z), "honest signature must verify");
        // Same (R, z) under a different message must not verify.
        assert!(!verify(&x, b"different message", &commitment, &z));
    }
}
