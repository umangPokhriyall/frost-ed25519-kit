//! RFC 9591 FROST(Ed25519, SHA-512) known-answer test — intermediates first
//! (phase1-spec §7.1, kickoff-amendment-1 §4).
//!
//! Vector: `tests/vectors/rfc9591_ed25519_sha512.json` (provenance in that file —
//! RFC 9591 Appendix C.1, retrieved 2026-06-18). The single official Ed25519
//! vector: a 2-of-3 group, signer set {1, 3}, message "test".
//!
//! The assertions are ordered and each gates the next, so a deviation in the rho
//! preimage encoding (a length prefix, the sort order, a domain label) surfaces at
//! the binding-factor stage with exact localization, not as an unattributable
//! failure at the final byte. The stages run as separate `#[test]`s so the runner
//! reports exactly which intermediates passed; on a real encoding bug the FIRST
//! failing stage names the layer to fix (against phase1-spec §3, not the final check).
//!
//! Everything is recomputed through `frost-core`'s own public primitives
//! (`ciphersuite::{h1,h2,h4,h5,encode_commitment_list}`, the group layer, and the
//! real `aggregate`/`verify`) — the encodings under test ARE the risk surface.
//! The hedged `commit`/`sign` nonce path is bypassed deliberately: the KAT pins the
//! math against the RFC's fixed nonces, which the hedged public API cannot inject.

use std::collections::BTreeMap;

use frost_core::ciphersuite;
use frost_core::group::{GElement, GScalar, Identifier};
use frost_core::keygen::PublicKeyPackage;
use frost_core::sign::{Signature, SignatureShare, SigningCommitments, aggregate};
use frost_core::verify::verify;

const VECTOR: &str = include_str!("vectors/rfc9591_ed25519_sha512.json");

fn hexb(s: &str) -> Vec<u8> {
    hex::decode(s).expect("vector hex")
}

fn arr32(s: &str) -> [u8; 32] {
    let v = hexb(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn scalar(s: &str) -> GScalar {
    GScalar::from_canonical_bytes(arr32(s)).expect("canonical scalar")
}

fn point(s: &str) -> GElement {
    GElement::from_compressed(arr32(s)).expect("prime-order point")
}

fn one() -> GScalar {
    let mut b = [0u8; 32];
    b[0] = 1;
    GScalar::from_canonical_bytes(b).unwrap()
}

struct Signer {
    id: u64,
    ident: Identifier,
    hiding_nonce: GScalar,
    binding_nonce: GScalar,
    big_d: GElement,
    big_e: GElement,
    rho_expected: [u8; 32],
    bfi_expected: Vec<u8>,
    z_expected: [u8; 32],
    share: GScalar,
}

struct Parsed {
    msg: Vec<u8>,
    group_public: GElement,
    threshold: u16,
    signers: Vec<Signer>,
    commitments: Vec<SigningCommitments>,
    all_shares: BTreeMap<u64, GScalar>,
    final_sig: Vec<u8>,
}

fn parse() -> Parsed {
    let v: serde_json::Value = serde_json::from_str(VECTOR).expect("vector json");

    let msg = hexb(v["inputs"]["message"].as_str().unwrap());
    let group_public = point(v["inputs"]["verifying_key_key"].as_str().unwrap());
    let threshold: u16 = v["config"]["MIN_PARTICIPANTS"].as_str().unwrap().parse().unwrap();

    let mut all_shares = BTreeMap::new();
    for ps in v["inputs"]["participant_shares"].as_array().unwrap() {
        let id = ps["identifier"].as_u64().unwrap();
        all_shares.insert(id, scalar(ps["participant_share"].as_str().unwrap()));
    }

    // Partial signatures, indexed by identifier.
    let mut z_by_id = BTreeMap::new();
    for o in v["round_two_outputs"]["outputs"].as_array().unwrap() {
        z_by_id.insert(o["identifier"].as_u64().unwrap(), arr32(o["sig_share"].as_str().unwrap()));
    }

    let mut signers = Vec::new();
    for o in v["round_one_outputs"]["outputs"].as_array().unwrap() {
        let id = o["identifier"].as_u64().unwrap();
        signers.push(Signer {
            id,
            ident: Identifier::try_from_u64(id).unwrap(),
            hiding_nonce: scalar(o["hiding_nonce"].as_str().unwrap()),
            binding_nonce: scalar(o["binding_nonce"].as_str().unwrap()),
            big_d: point(o["hiding_nonce_commitment"].as_str().unwrap()),
            big_e: point(o["binding_nonce_commitment"].as_str().unwrap()),
            rho_expected: arr32(o["binding_factor"].as_str().unwrap()),
            bfi_expected: hexb(o["binding_factor_input"].as_str().unwrap()),
            z_expected: z_by_id[&id],
            share: all_shares[&id],
        });
    }

    let commitments = signers
        .iter()
        .map(|s| SigningCommitments {
            id: s.ident,
            hiding: s.big_d,
            binding: s.big_e,
        })
        .collect();

    Parsed {
        msg,
        group_public,
        threshold,
        signers,
        commitments,
        all_shares,
        final_sig: hexb(v["final_output"]["sig"].as_str().unwrap()),
    }
}

impl Parsed {
    // The rho input prefix `group_public_enc ‖ H4(msg) ‖ H5(commitment_list)`
    // (RFC 9591 §4.4), recomputed through frost-core's public hashes.
    fn rho_prefix_parts(&self) -> ([u8; 32], [u8; 64], [u8; 64]) {
        let group_public_enc = self.group_public.to_compressed();
        let msg_hash = ciphersuite::h4(&self.msg);
        let com_hash = ciphersuite::h5(&ciphersuite::encode_commitment_list(&self.commitments));
        (group_public_enc, msg_hash, com_hash)
    }

    fn binding_factor_input(&self, s: &Signer) -> Vec<u8> {
        let (gp, mh, ch) = self.rho_prefix_parts();
        let mut out = Vec::new();
        out.extend_from_slice(&gp);
        out.extend_from_slice(&mh);
        out.extend_from_slice(&ch);
        out.extend_from_slice(&s.ident.as_scalar().to_bytes());
        out
    }

    fn rho(&self, s: &Signer) -> GScalar {
        let (gp, mh, ch) = self.rho_prefix_parts();
        let id_enc = s.ident.as_scalar().to_bytes();
        ciphersuite::h1(&[gp.as_slice(), mh.as_slice(), ch.as_slice(), id_enc.as_slice()])
    }

    // R = Σ_j (D_j + ρ_j·E_j).
    fn group_commitment(&self) -> GElement {
        let mut r = GElement::identity();
        for s in &self.signers {
            let rho = self.rho(s);
            r = r + s.big_d + s.big_e.scalar_mul(&rho);
        }
        r
    }

    // c = H2(R_enc ‖ A_enc ‖ msg).
    fn challenge(&self, r: &GElement) -> GScalar {
        let r_enc = r.to_compressed();
        let a_enc = self.group_public.to_compressed();
        ciphersuite::h2(&[r_enc.as_slice(), a_enc.as_slice(), &self.msg])
    }

    // λ_i over the signer set, interpolated at x = 0.
    fn lagrange(&self, ident: Identifier) -> GScalar {
        let xi = ident.as_scalar();
        let mut num = one();
        let mut den = one();
        for s in &self.signers {
            if s.ident == ident {
                continue;
            }
            let xj = s.ident.as_scalar();
            num = num * xj;
            den = den * (xj - xi);
        }
        num * den.invert()
    }
}

/// Stage 1a: the full rho input preimage `group_public_enc ‖ H4(msg) ‖
/// H5(commitment_list) ‖ id_enc` matches the vector — pins H4, H5, the
/// commitment-list encoding (sort + length), and the prefix order at once.
#[test]
fn stage1_binding_factor_input_matches() {
    let v = parse();
    for s in &v.signers {
        assert_eq!(
            v.binding_factor_input(s),
            s.bfi_expected,
            "binding_factor_input mismatch for signer {} — fix the H4/H5/encode_commitment_list or prefix order (phase1-spec §3)",
            s.id
        );
    }
}

/// Stage 1b: the binding factors `ρ_i = H1(input)` match for every signer.
#[test]
fn stage1_binding_factors_match() {
    let v = parse();
    for s in &v.signers {
        assert_eq!(
            v.rho(s).to_bytes(),
            s.rho_expected,
            "rho mismatch for signer {} — fix the H1 label/reduction (phase1-spec §3)",
            s.id
        );
    }
}

/// Stage 2: the group commitment `R = Σ_j (D_j + ρ_j·E_j)` matches `R_enc`, the
/// first 32 bytes of the final signature.
#[test]
fn stage2_group_commitment_matches() {
    let v = parse();
    let r = v.group_commitment();
    assert_eq!(
        &r.to_compressed()[..],
        &v.final_sig[0..32],
        "group commitment R mismatch"
    );
}

/// Stage 3: each partial `z_i = d_i + ρ_i·e_i + λ_i·c·s_i` matches the vector.
#[test]
fn stage3_partial_signatures_match() {
    let v = parse();
    let r = v.group_commitment();
    let c = v.challenge(&r);
    for s in &v.signers {
        let rho = v.rho(s);
        let lambda = v.lagrange(s.ident);
        let z = s.hiding_nonce + (rho * s.binding_nonce) + (lambda * c * s.share);
        assert_eq!(
            z.to_bytes(),
            s.z_expected,
            "partial z mismatch for signer {} — fix the challenge/Lagrange/partial formula",
            s.id
        );
    }
}

/// Stage 4: the final signature matches byte-for-byte AND `verify` accepts it.
/// Driven through the real `aggregate` (which re-derives R, ρ_j, c, λ_j, verifies
/// each partial against X_j, sums, and re-checks under RFC 8032) fed the vector's
/// partials — so this exercises the shipped aggregate/verify paths, not a
/// re-implementation.
#[test]
fn stage4_final_signature_matches_and_verifies() {
    let v = parse();

    let shares: Vec<SignatureShare> = v
        .signers
        .iter()
        .map(|s| SignatureShare {
            id: s.ident,
            z: GScalar::from_canonical_bytes(s.z_expected).unwrap(),
        })
        .collect();

    // X_i = s_i·G for the public key package (identifiable-abort check input).
    let g = GElement::generator();
    let mut verifying_shares = BTreeMap::new();
    for (id, s_i) in &v.all_shares {
        verifying_shares.insert(Identifier::try_from_u64(*id).unwrap(), g.scalar_mul(s_i));
    }
    let public = PublicKeyPackage {
        group_public: v.group_public,
        verifying_shares,
        threshold: v.threshold,
    };

    let sig = aggregate(&shares, &v.commitments, &public, &v.msg).expect("aggregate");
    assert_eq!(sig.to_bytes().as_slice(), v.final_sig.as_slice(), "final signature mismatch");
    assert!(verify(&v.group_public, &v.msg, &sig).is_ok(), "RFC 8032 verify rejected the KAT signature");

    // The 64-byte signature also round-trips through decode + verify.
    let decoded = Signature::from_bytes(sig.to_bytes()).unwrap();
    assert!(verify(&v.group_public, &v.msg, &decoded).is_ok());
}
