//! Pedersen verifiable distributed key generation (phase2-spec §4).
//!
//! Replaces the trusted dealer's *trust assumption* (see [`crate::keygen`]) with
//! a three-round protocol in which no single party ever holds the group secret.
//! It mirrors the `frost-core`/`frost-ed25519` `keys::dkg` API so the Phase 2
//! differential (phase2-spec §8.2) is clean, and it emits the **identical**
//! Phase 0 [`KeyPackage`] / [`PublicKeyPackage`] types so the frozen Phase 1
//! signing path consumes its output unchanged.
//!
//! The three rounds: `part1` samples a degree-`(t-1)` polynomial `f_i`, publishes
//! the Feldman commitment `φ_{i,k} = a_{i,k}·G`, and proves knowledge of its
//! constant term `a_{i,0}` (the rogue-key defence — Komlo–Goldberg §5, Gennaro et
//! al. biasing attack); `part2` verifies every peer's PoK and emits one private
//! share per recipient, naming a bad dealer with `Culprit(j)`; `part3` verifies
//! each received share against its sender's commitment (frozen `vss::verify_share`),
//! sums to the signing share, and derives the group key and verifying shares —
//! returning the unchanged Phase 0 `KeyPackage` / `PublicKeyPackage`. The DKG is
//! **abort-and-identify, not robust**: it cannot be biased, but a malicious dealer
//! can force an abort, and when it does the protocol names the culprit (§6).
//!
//! The one new hash-input encoding is the PoK challenge `H_dkg`; its label and
//! input order were **verified against `frost-ed25519` 2.2.0 source**, recorded
//! as named constants in [`crate::ciphersuite`], and are pinned deterministically
//! against the oracle by `tests/dkg_pok_pin.rs` before the full DKG is built
//! (phase2-spec §5).

use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::ciphersuite;
use crate::error::Error;
use crate::group::{GElement, GScalar, Identifier, validate_identifier_set};
use crate::keygen::{KeyPackage, PublicKeyPackage};
use crate::secret::SigningShare;
use crate::vss::{Commitments, verify_share, verifying_share};

/// A Schnorr proof of knowledge of the polynomial's constant term `a_{i,0}`
/// (phase2-spec §4): `σ_i = (R_i, μ_i)` with `R_i = k_i·G`,
/// `c_i = H_dkg(id_i ‖ φ_{i,0} ‖ R_i)`, `μ_i = k_i + a_{i,0}·c_i`. Verified by
/// checking `μ_i·G == R_i + c_i·φ_{i,0}`.
///
/// Carries **no secret**: `R_i` is a nonce commitment and `μ_i` is a Schnorr
/// response. It is broadcast in [`round1::Package`]; both fields are public.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProofOfKnowledge {
    /// `R_i = k_i·G` — the commitment to the (hedged, single-use) PoK nonce.
    pub r_commitment: GElement,
    /// `μ_i = k_i + a_{i,0}·c_i` — the Schnorr response.
    pub response: GScalar,
}

// Both fields are public proof material (a nonce commitment and a Schnorr
// response); a non-redacting Debug over their canonical encodings is safe.
// `GScalar` (frozen) has no Debug, so the response is printed as hex here.
impl core::fmt::Debug for ProofOfKnowledge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProofOfKnowledge { r_commitment: ")?;
        write!(f, "{:?}", self.r_commitment)?;
        f.write_str(", response: 0x")?;
        for byte in self.response.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(" }")
    }
}

/// The DKG PoK challenge `c_i = H_dkg(id_i ‖ φ_{i,0}_enc ‖ R_i_enc)` (phase2-spec
/// §4/§5). The input order — identifier, then the constant-term commitment
/// `φ_{i,0}`, then the nonce commitment `R_i`, each length-exactly 32 bytes — is
/// verified against `frost-core-2.2.0/src/keys/dkg.rs:412-430` (`challenge`), and
/// the `contextString ‖ "dkg"` prefix + wide reduction live in
/// [`ciphersuite::hdkg`]. This is the single new encoding; `tests/dkg_pok_pin.rs`
/// pins it against `frost-ed25519` before the full DKG runs.
pub fn pok_challenge(id: Identifier, phi0: &GElement, r_commitment: &GElement) -> GScalar {
    let id_enc = id.as_scalar().to_bytes();
    let phi0_enc = phi0.to_compressed();
    let r_enc = r_commitment.to_compressed();
    ciphersuite::hdkg(&[&id_enc, &phi0_enc, &r_enc])
}

/// DKG round 1 structures (phase2-spec §4).
pub mod round1 {
    use super::*;

    /// Kept private by the participant between rounds. Holds the secret
    /// polynomial `f_i`; consumed by `part2`. The coefficients are wrapped in
    /// [`Zeroizing`] so they are wiped on drop; the type carries no `Serialize`
    /// and only a redacting `Debug` (phase2-spec §4).
    pub struct SecretPackage {
        /// Coefficients `(a_{i,0}, …, a_{i,t-1})` of `f_i` (degree `t-1`). Read by
        /// `part2` to evaluate `f_i(ℓ)` for every recipient; held (zeroizing)
        /// between rounds and wiped when `part2` consumes the package.
        pub(crate) coefficients: Zeroizing<Vec<Scalar>>,
        /// This participant's identifier.
        pub(crate) id: Identifier,
        /// The minimum number of signers `t`.
        pub(crate) threshold: u16,
        /// The total number of signers `n`.
        pub(crate) max_signers: u16,
    }

    // Redacting Debug: never prints coefficient bytes (the secret polynomial).
    impl core::fmt::Debug for SecretPackage {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("round1::SecretPackage")
                .field("coefficients", &"<redacted>")
                .field("id", &self.id)
                .field("threshold", &self.threshold)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }

    /// Broadcast by the participant to all others between round 1 and round 2.
    /// Carries **no secret**: the Feldman commitments `φ_{i,0..t-1} = a_{i,k}·G`
    /// and the proof of knowledge of `a_{i,0}`.
    pub struct Package {
        /// `φ_{i,k} = a_{i,k}·G` for `k = 0..t-1`; `commitments.0[0]` is `φ_{i,0}`,
        /// the participant's public contribution to the group key.
        pub commitments: Commitments,
        /// Schnorr proof that the participant knows `a_{i,0}` (rogue-key defence).
        pub pok: ProofOfKnowledge,
    }

    // `vss::Commitments` (frozen) is neither Clone nor Debug, but its inner
    // `Vec<GElement>` is public and `GElement` is Copy, so the broadcast package
    // (no secret) can be cloned by rebuilding the commitment vector — useful for
    // orchestration, where each participant is handed the other peers' packages.
    impl Clone for Package {
        fn clone(&self) -> Self {
            Package {
                commitments: Commitments(self.commitments.0.clone()),
                pok: self.pok,
            }
        }
    }

    // All fields are public; `vss::Commitments` (frozen) has no Debug, so the
    // commitment points are listed via their own `GElement` Debug.
    impl core::fmt::Debug for Package {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("round1::Package")
                .field("commitments", &self.commitments.0)
                .field("pok", &self.pok)
                .finish()
        }
    }
}

/// Round 1: sample `f_i` (degree `t-1`), commit `φ_{i,k} = a_{i,k}·G`, and prove
/// knowledge of the constant term `a_{i,0}` (phase2-spec §4).
///
/// The PoK nonce is **hedged** against RNG failure (amendment §3, applied to the
/// PoK): `k_i = H3(random_bytes(32) ‖ encode(a_{i,0}))`. Mixing the secret
/// `a_{i,0}` into the nonce means a fully predictable RNG still cannot collide
/// `k_i` across distinct constant terms. `k_i` is single-use and zeroized the
/// moment the response is formed.
///
/// Rejects `threshold == 0` and `threshold > max_signers` with `InvalidThreshold`.
/// `id` is an [`Identifier`], so it is already validated nonzero by the frozen
/// group layer; the full participant-set (zero/duplicate) check runs once all
/// round-1 packages are present, in `part2`.
pub fn part1(
    id: Identifier,
    threshold: u16,
    max_signers: u16,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(round1::SecretPackage, round1::Package), Error> {
    if threshold == 0 || threshold > max_signers {
        return Err(Error::InvalidThreshold);
    }

    // Round 1, Step 1: sample t coefficients (a_{i,0}, …, a_{i,t-1}) ← Z_q.
    let t = threshold as usize;
    let coefficients: Vec<Scalar> = (0..t).map(|_| Scalar::random(rng)).collect();

    // Round 1, Step 3: φ_{i,k} = a_{i,k}·G. Only public points leave here.
    let g = GElement::generator();
    let commitments = Commitments(commit_coefficients(&coefficients));
    // t >= 1 guarantees a constant term; φ_{i,0} is the public contribution.
    let phi0 = commitments.0[0];

    // Round 1, Step 2: proof of knowledge of a_{i,0}, with a hedged PoK nonce.
    // encode(a_{i,0}): canonical 32-byte little-endian scalar — a work-path read
    // of the secret constant term; the buffer is zeroized below.
    let a0 = coefficients[0];
    let mut a0_enc = a0.to_bytes();
    let mut rand = [0u8; 32];
    rng.fill_bytes(&mut rand);

    // k_i = H3(random ‖ encode(a_{i,0})); held in Zeroizing so the single-use
    // nonce is wiped on drop the moment this function returns.
    let k = Zeroizing::new(ciphersuite::h3(&[rand.as_slice(), a0_enc.as_slice()]).as_scalar());
    let k_scalar = GScalar::from_scalar(*k);
    let r_commitment = g.scalar_mul(&k_scalar);
    let c = pok_challenge(id, &phi0, &r_commitment);
    // μ_i = k_i + a_{i,0}·c_i.
    let response = k_scalar + GScalar::from_scalar(a0) * c;

    a0_enc.zeroize();
    rand.zeroize();

    let secret = round1::SecretPackage {
        coefficients: Zeroizing::new(coefficients),
        id,
        threshold,
        max_signers,
    };
    let package = round1::Package {
        commitments,
        pok: ProofOfKnowledge {
            r_commitment,
            response,
        },
    };
    Ok((secret, package))
}

/// Feldman commitments `φ_k = a_k·G` for a coefficient vector. Returns only
/// public points; the secret coefficients never leave the caller. Shared by
/// `part1` (the broadcast commitment) and `part2` (recomputing the participant's
/// own commitment for `round2::SecretPackage`).
fn commit_coefficients(coeffs: &[Scalar]) -> Vec<GElement> {
    let g = GElement::generator();
    coeffs
        .iter()
        .map(|c| g.scalar_mul(&GScalar::from_scalar(*c)))
        .collect()
}

/// Evaluate `f_i(x)` at an identifier by Horner's method (the share `f_i(ℓ)`).
/// Operates on the raw secret coefficients; the result is wrapped immediately in
/// a [`SigningShare`] by the caller so it is zeroized on drop.
fn evaluate(coeffs: &[Scalar], id: Identifier) -> GScalar {
    let x = id.as_scalar().as_scalar();
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    GScalar::from_scalar(acc)
}

/// Verify a peer's proof of knowledge: `μ_j·G == R_j + c_j·φ_{j,0}` with
/// `c_j = H_dkg(j ‖ φ_{j,0} ‖ R_j)` (phase2-spec §4/§6). This is the rogue-key
/// defence — a participant cannot broadcast a `φ_{j,0}` chosen as a function of
/// others' contributions without knowing the matching `a_{j,0}` (Gennaro et al.
/// biasing attack).
fn pok_verifies(id: Identifier, phi0: &GElement, pok: &ProofOfKnowledge) -> bool {
    let c = pok_challenge(id, phi0, &pok.r_commitment);
    let lhs = GElement::generator().scalar_mul(&pok.response);
    let rhs = pok.r_commitment + phi0.scalar_mul(&c);
    lhs == rhs
}

/// DKG round 2 structures (phase2-spec §4, §7).
pub mod round2 {
    use super::*;

    /// One secret share `f_i(ℓ)` addressed to recipient `ℓ`. **Secret-in-transit**
    /// (phase2-spec §7): unlike the Phase 1 signing messages (which carry no
    /// secret), VSS *requires* a private dealer→recipient channel, so this share
    /// must cross one. The bounded deviation from the frozen `message.rs` rule
    /// ("no `Serialize` on a secret type") is surfaced, not smuggled:
    /// - the share is a [`SigningShare`] — `ZeroizeOnDrop`, redacting `Debug`, no
    ///   `serde` (the crate does not depend on `serde`);
    /// - [`serialize`](Self::serialize) emits raw bytes wrapped in [`Zeroizing`]
    ///   for transport **only over a private, authenticated channel** — the DKG's
    ///   stated transport trust assumption (recorded in `ARCHITECTURE.md`);
    /// - it never appears in a log and is consumed/zeroized in `part3`.
    #[derive(Debug)]
    pub struct Package {
        /// The recipient `ℓ` this share is addressed to. Public; lets `part3`
        /// reject a share misrouted to the wrong participant.
        pub recipient: Identifier,
        /// `f_i(ℓ)` — the secret share. Redacting `Debug`, zeroized on drop.
        pub(crate) share: SigningShare,
    }

    impl Package {
        /// Encode for transport as `recipient_enc(32) ‖ share_enc(32)`. The
        /// output contains secret key material, so it is returned in
        /// [`Zeroizing`]; send it **only** over a private, authenticated channel.
        pub fn serialize(&self) -> Zeroizing<Vec<u8>> {
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&self.recipient.as_scalar().to_bytes());
            out.extend_from_slice(&self.share.to_scalar().to_bytes());
            Zeroizing::new(out)
        }

        /// Decode a transported share. Rejects a wrong length, a non-canonical or
        /// zero recipient identifier (frozen group layer), and a non-canonical
        /// share scalar — reject, never coerce.
        pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() != 64 {
                return Err(Error::InvalidEncoding("dkg round2 package length"));
            }
            let mut id_b = [0u8; 32];
            id_b.copy_from_slice(&bytes[0..32]);
            let mut share_b = [0u8; 32];
            share_b.copy_from_slice(&bytes[32..64]);

            let recipient = Identifier::from_canonical_bytes(id_b)?;
            let share = SigningShare::from_canonical_bytes(share_b)?;
            share_b.zeroize();
            Ok(Package { recipient, share })
        }
    }

    /// Kept private by the participant between rounds 2 and 3. Holds the
    /// participant's own commitment `φ_i` (public), its own share `f_i(i)`
    /// (secret), and the protocol parameters. Zeroize-on-drop (via the
    /// [`SigningShare`] field), redacting `Debug`, never sent (phase2-spec §4).
    pub struct SecretPackage {
        /// This participant's identifier `i`.
        pub(crate) id: Identifier,
        /// `φ_{i,0..t-1} = a_{i,k}·G` — this participant's own commitment, summed
        /// into `group_public` and the verifying shares in `part3`.
        pub(crate) own_commitment: Commitments,
        /// `f_i(i)` — the participant's own secret share, kept (not transmitted)
        /// and added into `s_i` in `part3`.
        pub(crate) own_share: SigningShare,
        /// The minimum number of signers `t`.
        pub(crate) threshold: u16,
        /// The total number of signers `n`.
        pub(crate) max_signers: u16,
    }

    // Redacting Debug: never prints the own-share bytes. `Commitments` (frozen)
    // has no Debug, so only its length is shown.
    impl core::fmt::Debug for SecretPackage {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("round2::SecretPackage")
                .field("id", &self.id)
                .field("own_commitment_len", &self.own_commitment.0.len())
                .field("own_share", &"<redacted>")
                .field("threshold", &self.threshold)
                .field("max_signers", &self.max_signers)
                .finish()
        }
    }
}

/// Round 2: verify every peer's PoK and commitment, then emit one private share
/// per OTHER participant (phase2-spec §4, §6).
///
/// `round1_packages` carries the broadcast packages of the **other** `n-1`
/// participants (keyed by sender identifier; it must exclude this participant,
/// mirroring the `frost-core` `keys::dkg` convention so the Session 2.3
/// differential is clean). On an invalid PoK or a malformed commitment from peer
/// `j`, returns `Err(Culprit(j))` — naming the bad dealer (§6); a rogue-key
/// attempt (a `φ_{j,0}` without a valid PoK) is rejected here as `Culprit(j)`.
///
/// Returns the [`round2::SecretPackage`] (kept for `part3`, holding `f_i(i)`) and
/// one [`round2::Package`] per recipient `ℓ ≠ i`, each carrying `f_i(ℓ)` to be
/// sent over a private, authenticated channel (§7). The round-1 secret
/// polynomial is consumed by value and zeroized when this call returns.
pub fn part2(
    secret: round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
) -> Result<(round2::SecretPackage, BTreeMap<Identifier, round2::Package>), Error> {
    let my_id = secret.id;
    let t = secret.threshold as usize;
    let n = secret.max_signers as usize;

    // Identifier discipline (amendment §5, via the frozen layer): the full set —
    // the n-1 peers plus self — must be free of zero/duplicate identifiers. Self
    // appearing among the peers is a duplicate -> DuplicateIdentifier; zero cannot
    // occur because Identifier construction already rejects it.
    let mut all_ids: Vec<Identifier> = round1_packages.keys().copied().collect();
    all_ids.push(my_id);
    validate_identifier_set(&all_ids)?;
    // Count must be exact, or group_public would silently miss a contribution.
    if round1_packages.len() != n - 1 {
        return Err(Error::InvalidEncoding("dkg: incorrect number of round1 packages"));
    }

    // Verify every peer's PoK and commitment. (Each φ_{j,k} is a `GElement`, so
    // the frozen group layer already rejected any non-prime-order point at
    // deserialization; here we check the commitment degree and the PoK.)
    for (&j, package) in round1_packages {
        if package.commitments.0.len() != t {
            return Err(Error::Culprit(j));
        }
        let phi_j0 = package.commitments.0[0];
        if !pok_verifies(j, &phi_j0, &package.pok) {
            return Err(Error::Culprit(j));
        }
    }

    // Recompute my own commitment φ_i from f_i (kept for part3).
    let own_commitment = Commitments(commit_coefficients(&secret.coefficients));

    // Emit one share f_i(ℓ) per other participant ℓ; keep f_i(i) for myself.
    let mut round2_packages = BTreeMap::new();
    for &ell in round1_packages.keys() {
        let share = SigningShare::from_scalar(evaluate(&secret.coefficients, ell));
        round2_packages.insert(ell, round2::Package { recipient: ell, share });
    }
    let own_share = SigningShare::from_scalar(evaluate(&secret.coefficients, my_id));

    let secret2 = round2::SecretPackage {
        id: my_id,
        own_commitment,
        own_share,
        threshold: secret.threshold,
        max_signers: secret.max_signers,
    };
    // `secret` (the round-1 polynomial) drops here, zeroizing its coefficients.
    Ok((secret2, round2_packages))
}

/// Round 3: verify each received share against its sender's commitment, then sum
/// to the long-lived signing share and derive the group key and all verifying
/// shares (phase2-spec §4, §6).
///
/// `round2_packages` are the shares addressed to this participant, keyed by
/// sender identifier (the same `n-1` peers as `round1_packages`). Each share
/// `f_j(i)` is checked with the frozen [`verify_share`] against dealer `j`'s
/// commitment; on failure returns `Err(Culprit(j))` (§6). Then
/// `s_i = Σ_j f_j(i) + f_i(i)` (zeroizing accumulation), `group_public = Σ_j
/// φ_{j,0}`, and `verifying_shares[ℓ] = Σ_j verifying_share(ℓ, commitments_j)`
/// for every participant `ℓ`. Returns the **identical Phase 0**
/// [`KeyPackage`] / [`PublicKeyPackage`] the trusted dealer produced, so the
/// frozen Phase 1 signing path consumes the output unchanged.
pub fn part3(
    secret: &round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier, round1::Package>,
    round2_packages: &BTreeMap<Identifier, round2::Package>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    let my_id = secret.id;
    let n = secret.max_signers as usize;

    // Identifier discipline (amendment §5, via the frozen layer): peers plus self
    // must be free of zero/duplicate identifiers (self among the peers ->
    // DuplicateIdentifier). Reused below for the verifying-share derivation.
    let mut all_ids: Vec<Identifier> = round1_packages.keys().copied().collect();
    all_ids.push(my_id);
    validate_identifier_set(&all_ids)?;
    if round1_packages.len() != n - 1 || round2_packages.len() != n - 1 {
        return Err(Error::InvalidEncoding("dkg: incorrect number of packages"));
    }

    // Verify each received share f_j(i) against dealer j's commitment, summing
    // s_i = Σ_j f_j(i) in a zeroizing accumulator.
    let mut s = Zeroizing::new(Scalar::ZERO);
    for (&sender, package) in round2_packages {
        if package.recipient != my_id {
            return Err(Error::InvalidEncoding(
                "dkg: round2 package addressed to wrong recipient",
            ));
        }
        let sender_commitment = &round1_packages
            .get(&sender)
            .ok_or(Error::InvalidEncoding("dkg: round2 sender has no round1 package"))?
            .commitments;
        // Frozen vss::verify_share: f_j(i)·G == Σ_k φ_{j,k}·i^k. Remap the
        // generic InvalidShare to Culprit(sender) — name the bad dealer (§6).
        verify_share(my_id, &package.share, sender_commitment).map_err(|_| Error::Culprit(sender))?;
        *s += package.share.to_scalar().as_scalar();
    }
    // Add my own kept share f_i(i).
    *s += secret.own_share.to_scalar().as_scalar();
    let signing_share = SigningShare::from_scalar(GScalar::from_scalar(*s));

    // group_public = Σ_j φ_{j,0} over all participants (peers + self).
    let mut group_public = secret.own_commitment.0[0];
    for package in round1_packages.values() {
        group_public = group_public + package.commitments.0[0];
    }

    // verifying_shares[ℓ] = Σ_j verifying_share(ℓ, commitments_j) for every ℓ.
    let mut verifying_shares = BTreeMap::new();
    for &ell in &all_ids {
        let mut acc = verifying_share(ell, &secret.own_commitment);
        for package in round1_packages.values() {
            acc = acc + verifying_share(ell, &package.commitments);
        }
        verifying_shares.insert(ell, acc);
    }

    let verifying_share = *verifying_shares
        .get(&my_id)
        .ok_or(Error::InvalidEncoding("dkg: missing own verifying share"))?;

    let key_package = KeyPackage {
        id: my_id,
        signing_share,
        verifying_share,
    };
    let public = PublicKeyPackage {
        group_public,
        verifying_shares,
        threshold: secret.threshold,
    };
    Ok((key_package, public))
}

#[cfg(test)]
mod tests {
    //! In-process orchestration of the full DKG (phase2-spec §4): part1 →
    //! part2 → part3 across all participants. This is the Session 2.2 done-when
    //! — a complete `frost-core` DKG produces a `KeyPackage`/`PublicKeyPackage`
    //! set. The interop-vs-`frost-ed25519`, reconstruction, DKG→sign→verify, and
    //! adversarial gates are Session 2.3 (`tests/dkg_differential.rs`,
    //! `tests/dkg_adversarial.rs`).

    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// The other participants' round-1 packages, with `self` removed (the
    /// exclude-self input convention of `part2`/`part3`).
    fn peers_of(
        all: &BTreeMap<Identifier, round1::Package>,
        me: Identifier,
    ) -> BTreeMap<Identifier, round1::Package> {
        all.iter()
            .filter(|(id, _)| **id != me)
            .map(|(&id, pkg)| (id, pkg.clone()))
            .collect()
    }

    /// Drive a full `t`-of-`n` DKG in process. Returns one `KeyPackage` per
    /// participant and the `PublicKeyPackage` each derived (one per participant,
    /// for the cross-participant consensus checks).
    fn run_dkg(
        threshold: u16,
        n: u16,
        seed: u64,
    ) -> (
        BTreeMap<Identifier, KeyPackage>,
        BTreeMap<Identifier, PublicKeyPackage>,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let ids: Vec<Identifier> = (1..=n as u64)
            .map(|i| Identifier::try_from_u64(i).unwrap())
            .collect();

        // Round 1: every participant broadcasts its commitment + PoK.
        let mut secrets1 = BTreeMap::new();
        let mut round1_all = BTreeMap::new();
        for &id in &ids {
            let (s1, pkg1) = part1(id, threshold, n, &mut rng).unwrap();
            secrets1.insert(id, s1);
            round1_all.insert(id, pkg1);
        }

        // Round 2: each participant verifies peers and emits one share per
        // recipient. Route share-to-ℓ from sender s into recipient ℓ's inbox,
        // keyed by sender.
        let mut secrets2 = BTreeMap::new();
        let mut inbox: BTreeMap<Identifier, BTreeMap<Identifier, round2::Package>> =
            ids.iter().map(|&id| (id, BTreeMap::new())).collect();
        for &id in &ids {
            let s1 = secrets1.remove(&id).unwrap();
            let (s2, outgoing) = part2(s1, &peers_of(&round1_all, id)).unwrap();
            secrets2.insert(id, s2);
            for (recipient, pkg) in outgoing {
                inbox.get_mut(&recipient).unwrap().insert(id, pkg);
            }
        }

        // Round 3: each participant verifies received shares and derives its key.
        let mut key_packages = BTreeMap::new();
        let mut public_packages = BTreeMap::new();
        for &id in &ids {
            let received = inbox.remove(&id).unwrap();
            let (kp, pkp) =
                part3(&secrets2[&id], &peers_of(&round1_all, id), &received).unwrap();
            key_packages.insert(id, kp);
            public_packages.insert(id, pkp);
        }
        (key_packages, public_packages)
    }

    fn check_full_dkg(threshold: u16, n: u16, seed: u64) {
        let (key_packages, public_packages) = run_dkg(threshold, n, seed);
        assert_eq!(key_packages.len(), n as usize);
        assert_eq!(public_packages.len(), n as usize);

        let ids: Vec<Identifier> = key_packages.keys().copied().collect();

        // All participants agree on the group key and on every verifying share.
        let reference = &public_packages[&ids[0]];
        for id in &ids {
            let pkp = &public_packages[id];
            assert_eq!(pkp.threshold, threshold);
            assert!(
                reference.group_public == pkp.group_public,
                "participants disagree on group_public"
            );
            for ell in &ids {
                assert!(
                    reference.verifying_shares[ell] == pkp.verifying_shares[ell],
                    "participants disagree on a verifying share"
                );
            }
        }

        // Every signing share is consistent with its published verifying share:
        // s_i·G == X_i, and X_i equals the public package's entry for i.
        let g = GElement::generator();
        for id in &ids {
            let kp = &key_packages[id];
            let s_i_g = g.scalar_mul(&kp.signing_share.to_scalar());
            assert!(s_i_g == kp.verifying_share, "s_i·G != X_i");
            assert!(
                kp.verifying_share == reference.verifying_shares[id],
                "KeyPackage X_i != PublicKeyPackage verifying_shares[i]"
            );
        }
    }

    #[test]
    fn full_dkg_2_of_3_produces_a_valid_key_set() {
        check_full_dkg(2, 3, 0x2_0_3);
    }

    #[test]
    fn full_dkg_3_of_5_produces_a_valid_key_set() {
        check_full_dkg(3, 5, 0x3_0_5);
    }

    #[test]
    fn round2_package_serialize_roundtrip() {
        let (_, outgoing) = {
            let mut rng = StdRng::seed_from_u64(202);
            let (s1, _) = part1(Identifier::try_from_u64(1).unwrap(), 2, 3, &mut rng).unwrap();
            // Build a one-peer round-1 set so part2 emits a share to that peer.
            let (_, peer_pkg) = part1(Identifier::try_from_u64(2).unwrap(), 2, 3, &mut rng).unwrap();
            let (_, peer_pkg3) = part1(Identifier::try_from_u64(3).unwrap(), 2, 3, &mut rng).unwrap();
            let mut peers = BTreeMap::new();
            peers.insert(Identifier::try_from_u64(2).unwrap(), peer_pkg);
            peers.insert(Identifier::try_from_u64(3).unwrap(), peer_pkg3);
            part2(s1, &peers).unwrap()
        };
        let recipient = Identifier::try_from_u64(2).unwrap();
        let pkg = &outgoing[&recipient];
        let bytes = pkg.serialize();
        let decoded = round2::Package::deserialize(&bytes).unwrap();
        assert_eq!(decoded.recipient, recipient);
        assert!(
            decoded.share.to_scalar() == pkg.share.to_scalar(),
            "round2 share did not survive serialize/deserialize"
        );
    }
}
