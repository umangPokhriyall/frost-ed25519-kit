//! The Benhamouda–Lefranc–Loss–Orsini–Raykova (2020) polynomial-time ROS solver
//! (phase3-spec §3, kickoff-amendment-1 §1) — the Phase 3 headline attack.
//!
//! # What this forges, and why it works
//!
//! The naive scheme reduces to single-key concurrent Schnorr (see
//! [`crate::oracle`] for the reduction). Each open session hands out a commitment
//! `R_i = r_i·G`; signing it on a message `m` returns `z_i = r_i + c_i·s` with the
//! per-session challenge `c_i = H(R_i ‖ X ‖ m)` a **public function of `(R_i, m)`
//! alone**. That last property is the entire vulnerability: the adversary can
//! predict every challenge before deciding which messages to actually sign.
//!
//! The forgery is a fixed linear combination of the sessions. Pick coefficients
//! `a_i` and set
//!
//! ```text
//!   R* = Σ a_i·R_i ,   z* = Σ a_i·z_i .
//! ```
//!
//! Then `z*·G = Σ a_i·(R_i + c_i·s)·G = R* + (Σ a_i·c_i)·X`, so `(R*, z*)` is a
//! valid signature on a target `m*` **iff** `Σ a_i·c_i = c* = H(R* ‖ X ‖ m*)`.
//! The solver forces that single scalar equation with the BLLOR binary-
//! decomposition trick:
//!
//! 1. Open `ℓ` sessions (use `ℓ = 256 > log2(L)` for the ~2^252 edwards25519
//!    order, with slack — kickoff-amendment-1 §1). Collect `R_0 … R_{ℓ-1}`.
//! 2. For each session `i`, query the challenge on **two** messages, obtaining
//!    `c_i^0 = H(R_i ‖ X ‖ m_i^0)` and `c_i^1 = H(R_i ‖ X ‖ m_i^1)` with
//!    `c_i^1 ≠ c_i^0`. (These are public-hash evaluations; the secret is never
//!    touched.)
//! 3. Set `a_i = 2^i · (c_i^1 − c_i^0)^{-1}`. This freezes `R* = Σ a_i·R_i` and the
//!    constant `K = Σ a_i·c_i^0`, both independent of the later bit choices.
//! 4. Compute the target challenge `c* = H(R* ‖ X ‖ m*)` and the residue
//!    `T = c* − K`. Read `T`'s little-endian bits `b_0 … b_{ℓ-1}` (`T < L < 2^ℓ`,
//!    so every residue is representable).
//! 5. Close each session by signing `m_i^{b_i}` (a single signing query per
//!    session). Because `a_i·c_i^{b_i} = a_i·c_i^0 + b_i·2^i`,
//!
//!    ```text
//!      Σ a_i·c_i^{b_i} = K + Σ b_i·2^i = K + T = c* .
//!    ```
//!
//! So `(R*, z*)` verifies on `m*`, a message no session ever signed.
//!
//! # The structural invariant — and why FROST denies it
//!
//! Step 3 onward presumes one algebraic fact: each session is a **homomorphic
//! Schnorr response**, `z_i·G == R_i + H(R_i ‖ X ‖ m)·X`, with the challenge a
//! function of `(R_i, m)` only. [`ros_attack`] asserts exactly this on every
//! closed session; when it holds, the linear system above exists and the forgery
//! lands. When it does **not** hold — as for FROST, whose binding factor makes the
//! effective per-session commitment and challenge depend on the message *and the
//! full commitment list* — the system the solver needs does not exist, and
//! [`ros_attack`] returns [`RosOutcome::NoSolution`]. The negative control in
//! `frost-core/tests/ros_resistance.rs` drives that path and carries the full
//! binding-factor argument.
//!
//! The solver is handed **only** the public key `X` and the oracle handle (the
//! [`SchnorrLikeOracle`] trait exposes no secret); a forgery therefore cannot
//! secretly consult `s`.

use std::time::{Duration, Instant};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

/// The only interface the ROS solver has to a signer. It exposes the public key,
/// concurrent session opening, the **public** per-session challenge function, and
/// signing — never the secret. Any oracle whose responses are homomorphic Schnorr
/// (`z_i·G == R_i + challenge(R_i, m)·X`) is forgeable by [`ros_attack`]; one whose
/// responses are not (FROST) yields [`RosOutcome::NoSolution`].
pub trait SchnorrLikeOracle {
    /// Opaque session handle.
    type Session: Copy;

    /// The group public key `X` (`= s·G`). No secret is exposed.
    fn public_key(&self) -> EdwardsPoint;

    /// Open a fresh concurrent session, returning its handle and commitment `R_i`.
    fn open_session(&mut self) -> (Self::Session, EdwardsPoint);

    /// The challenge scalar this oracle applies to the secret when a session with
    /// commitment `r_i` is signed on `msg`. The ROS attack **requires** this be a
    /// pure function of `(r_i, msg)`, predictable before any signing query.
    fn challenge(&self, r_i: &EdwardsPoint, msg: &[u8]) -> Scalar;

    /// Sign `msg` under an open session, returning the response `z_i`.
    fn sign(&mut self, session: Self::Session, msg: &[u8]) -> Scalar;
}

/// A forged signature `(R*, z*)` in the oracle's native encoding, checkable with
/// [`crate::verify`].
#[derive(Clone, Debug)]
pub struct Forgery {
    /// `R*` — the forged commitment, compressed.
    pub commitment: CompressedEdwardsY,
    /// `z*` — the forged response scalar.
    pub response: Scalar,
}

/// The outcome of [`ros_attack`].
pub enum RosOutcome {
    /// A verifying forgery on `m_star`, which is provably absent from
    /// `signed_messages` (the messages actually queried).
    Forged {
        /// The forged `(R*, z*)`.
        sig: Forgery,
        /// The target message `m*` — outside `signed_messages`.
        m_star: Vec<u8>,
        /// Every message the solver had the oracle sign; `m_star ∉` this set.
        signed_messages: Vec<Vec<u8>>,
        /// Number of concurrent sessions opened (`ℓ`).
        sessions: usize,
        /// Wall-clock from first session open to verified forgery.
        elapsed: Duration,
    },
    /// The oracle is not a homomorphic Schnorr signer (e.g. FROST's binding
    /// factor): the linear system the solver requires does not exist. This is a
    /// **structural** verdict, not a count of failed attempts.
    NoSolution,
}

/// `c = H(R ‖ X ‖ msg)` over SHA-512, reduced wide. Mirrors the private
/// `oracle::challenge` exactly (verified against `oracle.rs`); kept here so the
/// solver predicts challenges without modifying the frozen oracle. Any divergence
/// would make the forgery fail [`crate::verify`], which is the success gate.
pub fn schnorr_challenge(commitment: &CompressedEdwardsY, public: &CompressedEdwardsY, msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(commitment.as_bytes());
    h.update(public.as_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(h.finalize().as_slice());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The polynomial-time BLLOR ROS forgery (module docs for the construction).
///
/// Opens `ell` sessions on `oracle`, forges a signature on `target`, and returns
/// [`RosOutcome::Forged`] only if it **verifies under the standard equation**
/// `z*·G == R* + H(R* ‖ X ‖ m*)·X` and `target` is outside the signed set. If the
/// oracle's responses are not homomorphic Schnorr, returns
/// [`RosOutcome::NoSolution`]. Never consults the secret.
///
/// # Panics
/// Panics (a deliberate STOP, per phase3-spec §3.1) if a verifying forgery is
/// produced on a `target` that *is* in the signed set — an in-set "forgery" is a
/// strawman, not a pass.
pub fn ros_attack<O: SchnorrLikeOracle>(oracle: &mut O, ell: usize, target: &[u8]) -> RosOutcome {
    let start = Instant::now();
    let x = oracle.public_key();

    // 1. Open `ell` concurrent sessions; collect the commitments R_i.
    let mut sessions = Vec::with_capacity(ell);
    let mut r = Vec::with_capacity(ell);
    for _ in 0..ell {
        let (sid, r_i) = oracle.open_session();
        sessions.push(sid);
        r.push(r_i);
    }

    // 2. Per session, two messages giving two distinct challenges c_i^0, c_i^1.
    let mut m0 = Vec::with_capacity(ell);
    let mut m1 = Vec::with_capacity(ell);
    let mut c0 = Vec::with_capacity(ell);
    let mut c1 = Vec::with_capacity(ell);
    for (i, r_i) in r.iter().enumerate() {
        let (a0, ch0, a1, ch1) = two_distinct_challenges(oracle, r_i, i);
        m0.push(a0);
        c0.push(ch0);
        m1.push(a1);
        c1.push(ch1);
    }

    // 3. a_i = 2^i·(c_i^1 − c_i^0)^{-1}; R* = Σ a_i·R_i; K = Σ a_i·c_i^0.
    let mut a = Vec::with_capacity(ell);
    let mut weight = Scalar::ONE; // 2^i, accumulated mod L
    let two = Scalar::from(2u64);
    let mut r_star = EdwardsPoint::identity();
    let mut k = Scalar::ZERO;
    for i in 0..ell {
        let a_i = weight * (c1[i] - c0[i]).invert();
        r_star += r[i] * a_i;
        k += a_i * c0[i];
        a.push(a_i);
        weight *= two;
    }

    // 4. Target challenge and the residue T = c* − K, read as ℓ little-endian bits.
    let c_star = oracle.challenge(&r_star, target);
    let t = c_star - k;
    let t_bytes = t.to_bytes(); // canonical little-endian, value in [0, L) < 2^ℓ

    // 5. Close each session by signing m_i^{b_i}; verify the homomorphic-Schnorr
    //    invariant the linear system rests on; accumulate z* = Σ a_i·z_i.
    let mut z_star = Scalar::ZERO;
    let mut signed_messages = Vec::with_capacity(ell);
    for i in 0..ell {
        let bit = (t_bytes[i / 8] >> (i % 8)) & 1;
        let (msg, c_used) = if bit == 1 { (m1[i].clone(), c1[i]) } else { (m0[i].clone(), c0[i]) };
        let z_i = oracle.sign(sessions[i], &msg);

        // The ROS linear system presumes z_i·G == R_i + challenge(R_i, msg)·X.
        // True for a homomorphic Schnorr oracle; FALSE for FROST, whose effective
        // commitment R_i + ρ_i(msg)·E_i and challenge both move with the message.
        // Its failure means the system does not exist -> NoSolution (structural).
        if ED25519_BASEPOINT_POINT * z_i != r[i] + x * c_used {
            return RosOutcome::NoSolution;
        }

        z_star += a[i] * z_i;
        signed_messages.push(msg);
    }

    // 6. Success gate (phase3-spec §3.1.1): the standard verification equation.
    if ED25519_BASEPOINT_POINT * z_star != r_star + x * c_star {
        return RosOutcome::NoSolution;
    }

    // phase3-spec §3.1.2: the forged message must be outside the signed set.
    assert!(
        !signed_messages.iter().any(|m| m.as_slice() == target),
        "STOP: target message is in the signed set — an in-set forgery is a strawman"
    );

    RosOutcome::Forged {
        sig: Forgery { commitment: r_star.compress(), response: z_star },
        m_star: target.to_vec(),
        signed_messages,
        sessions: ell,
        elapsed: start.elapsed(),
    }
}

/// Two messages for session `i` and their (distinct) challenges. Distinctness is
/// needed so `(c_i^1 − c_i^0)` is invertible; SHA-512 collisions are negligible,
/// but the salt loop makes the guard explicit. All messages share the `ros-sess/`
/// prefix so the caller's `target` stays trivially out of the signed set.
fn two_distinct_challenges<O: SchnorrLikeOracle>(
    oracle: &O,
    r_i: &EdwardsPoint,
    i: usize,
) -> (Vec<u8>, Scalar, Vec<u8>, Scalar) {
    let mut salt = 0u64;
    loop {
        let a0 = format!("ros-sess/{i}/0/{salt}").into_bytes();
        let a1 = format!("ros-sess/{i}/1/{salt}").into_bytes();
        let ch0 = oracle.challenge(r_i, &a0);
        let ch1 = oracle.challenge(r_i, &a1);
        if ch0 != ch1 {
            return (a0, ch0, a1, ch1);
        }
        salt += 1;
    }
}

// The legacy oracle is itself a homomorphic Schnorr signer: it is the attack
// target. The adapter is here (not in the test) so both the artifact-writing test
// below and `frost-core`'s `ros_resistance.rs` drive the same oracle the same way.
impl<R: rand::RngCore + rand::CryptoRng> SchnorrLikeOracle for crate::oracle::NaiveSchnorrOracle<R> {
    type Session = crate::oracle::SessionId;

    fn public_key(&self) -> EdwardsPoint {
        crate::oracle::NaiveSchnorrOracle::public_key(self)
    }

    fn open_session(&mut self) -> (Self::Session, EdwardsPoint) {
        let (sid, commitment) = crate::oracle::NaiveSchnorrOracle::open_session(self);
        let r_i = commitment
            .decompress()
            .expect("oracle commitment R_i = r_i·G is always a valid point");
        (sid, r_i)
    }

    fn challenge(&self, r_i: &EdwardsPoint, msg: &[u8]) -> Scalar {
        schnorr_challenge(&r_i.compress(), &self.public_key().compress(), msg)
    }

    fn sign(&mut self, session: Self::Session, msg: &[u8]) -> Scalar {
        crate::oracle::NaiveSchnorrOracle::sign(self, session, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::NaiveSchnorrOracle;
    use rand::rngs::OsRng;

    /// `ℓ = 256` per kickoff-amendment-1 §1 (one bit per ~2^252 order bit, plus
    /// slack).
    const ELL: usize = 256;

    // The headline artifact: forge against the construction the repo used to ship,
    // and commit `legacy/results/ros_forgery.txt` (phase3-spec §3.3).
    #[test]
    fn ros_forges_legacy_oracle_and_writes_artifact() {
        let mut oracle = NaiveSchnorrOracle::new(OsRng);
        let x = oracle.public_key();
        let target = b"FORGERY: this message was never signed by any honest session".to_vec();

        let outcome = ros_attack(&mut oracle, ELL, &target);

        let (sig, m_star, signed_messages, sessions, elapsed) = match outcome {
            RosOutcome::Forged { sig, m_star, signed_messages, sessions, elapsed } => {
                (sig, m_star, signed_messages, sessions, elapsed)
            }
            RosOutcome::NoSolution => panic!("STOP: solver found no forgery against the legacy oracle"),
        };

        // §3.1.1: the forgery must verify under the legacy standard equation.
        assert!(
            crate::verify(&x, &m_star, &sig.commitment, &sig.response),
            "STOP: forged (R*, z*) does not verify"
        );
        // §3.1.2: m* is provably outside the signed set.
        assert!(
            !signed_messages.contains(&m_star),
            "STOP: m* is in the signed set"
        );
        assert_eq!(sessions, ELL);

        // Commit the artifact: ℓ, wall-clock, m*, and the out-of-set proof.
        let path = format!("{}/results/ros_forgery.txt", env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(format!("{}/results", env!("CARGO_MANIFEST_DIR")))
            .expect("create results dir");
        let m_star_str = String::from_utf8_lossy(&m_star);
        let contents = format!(
            "ROS forgery against the legacy naive-Schnorr oracle (BLLOR 2020)\n\
             ================================================================\n\
             ℓ={ell} sessions, forgery in {ms} ms\n\
             \n\
             m* = {m_star:?}\n\
             m*  verifies under [8]·z*·G == [8]·(R* + H(R* ‖ X ‖ m*)·X): yes\n\
             \n\
             out-of-set proof: every signed message is prefixed \"ros-sess/\";\n\
             m* (prefixed \"FORGERY:\") is not among the {n} signed messages,\n\
             so m* ∉ {{m_0, …, m_{last}}}.\n",
            ell = sessions,
            ms = elapsed.as_secs_f64() * 1000.0,
            m_star = m_star_str,
            n = signed_messages.len(),
            last = signed_messages.len() - 1,
        );
        std::fs::write(&path, contents).expect("write ros_forgery.txt");
    }
}
