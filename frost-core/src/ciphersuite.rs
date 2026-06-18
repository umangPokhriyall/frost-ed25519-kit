//! FROST(Ed25519, SHA-512) ciphersuite constants and hash functions (phase1-spec §3).
//!
//! Hand-rolling FROST means the hash-input encodings are the entire risk surface,
//! so every label, the contextString, and the commitment-list encoding here was
//! **verified against RFC 9591 §6.1 and the `frost-ed25519` v2.2.0 source**, not
//! assumed; each constant carries its provenance. The intermediate KATs
//! (phase1-spec §7) are the guard that catches a one-byte deviation.
//!
//! Verification sources (read 2026-06-18):
//! - RFC 9591 §6.1 (FROST(Ed25519, SHA-512)) and §4.4 (binding factors).
//! - `frost-ed25519-2.2.0/src/lib.rs:142-160,179-207` (H1–H5, contextString).
//! - `frost-core-2.2.0/src/lib.rs:415-447` (rho input prefix) and
//!   `frost-core-2.2.0/src/round1.rs:392-404` (commitment-list encoding).

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::group::GScalar;
use crate::sign::SigningCommitments;

/// RFC 9591 §6.1: the FROST(Ed25519, SHA-512) contextString. Verified byte-for-byte
/// against `frost-ed25519-2.2.0/src/lib.rs:160` (`"FROST-ED25519-SHA512-v1"`).
pub const CONTEXT_STRING: &[u8] = b"FROST-ED25519-SHA512-v1";

/// RFC 9591 §6.1 H1 (binding factor / rho) domain label.
/// `frost-ed25519-2.2.0/src/lib.rs:179` — `hash_to_scalar([contextString, b"rho", m])`.
pub const H1_LABEL: &[u8] = b"rho";

/// RFC 9591 §6.1 H3 (nonce derivation) domain label.
/// `frost-ed25519-2.2.0/src/lib.rs:193` — `hash_to_scalar([contextString, b"nonce", m])`.
pub const H3_LABEL: &[u8] = b"nonce";

/// RFC 9591 §6.1 H4 (message hash) domain label.
/// `frost-ed25519-2.2.0/src/lib.rs:200` — `hash_to_array([contextString, b"msg", m])`.
pub const H4_LABEL: &[u8] = b"msg";

/// RFC 9591 §6.1 H5 (commitment-list hash) domain label.
/// `frost-ed25519-2.2.0/src/lib.rs:207` — `hash_to_array([contextString, b"com", m])`.
pub const H5_LABEL: &[u8] = b"com";

// RFC 9591 §6.1 H2 (challenge) has NO contextString and NO label: it is
// `hash_to_scalar([m])` (`frost-ed25519-2.2.0/src/lib.rs:186`), so the challenge
// `H2(R_enc ‖ A_enc ‖ msg)` equals the RFC 8032 challenge and the output verifies
// under an off-the-shelf Ed25519 verifier. The absence of a label is the point,
// so there is no H2 constant.

/// SHA-512 over the concatenation of `parts`, returned as the raw 64-byte digest.
/// Mirrors `frost-ed25519-2.2.0/src/lib.rs:142` `hash_to_array`.
fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// SHA-512 over `parts`, reduced mod L over the full 64-byte (wide) output.
/// Mirrors `frost-ed25519-2.2.0/src/lib.rs:152` `hash_to_scalar`
/// (`Scalar::from_bytes_mod_order_wide`). The wide reduction — never a 32-byte
/// truncation — is part of the contract.
fn reduce_wide(parts: &[&[u8]]) -> GScalar {
    GScalar::from_scalar(Scalar::from_bytes_mod_order_wide(&sha512(parts)))
}

/// Prepend `prefix` to `parts` without copying the underlying bytes.
fn with_prefix<'a>(prefix: &[&'a [u8]], parts: &[&'a [u8]]) -> Vec<&'a [u8]> {
    let mut all = Vec::with_capacity(prefix.len() + parts.len());
    all.extend_from_slice(prefix);
    all.extend_from_slice(parts);
    all
}

/// RFC 9591 §6.1 H1: binding factor `ρ = H(contextString ‖ "rho" ‖ m) mod L`.
pub fn h1(parts: &[&[u8]]) -> GScalar {
    reduce_wide(&with_prefix(&[CONTEXT_STRING, H1_LABEL], parts))
}

/// RFC 9591 §6.1 H2: challenge `c = SHA-512(m) mod L`. NO contextString / label
/// (Ed25519 / RFC 8032 verifier compatibility).
pub fn h2(parts: &[&[u8]]) -> GScalar {
    reduce_wide(parts)
}

/// RFC 9591 §6.1 H3: nonce `H(contextString ‖ "nonce" ‖ m) mod L` (hedged commit).
pub fn h3(parts: &[&[u8]]) -> GScalar {
    reduce_wide(&with_prefix(&[CONTEXT_STRING, H3_LABEL], parts))
}

/// RFC 9591 §6.1 H4: message hash `H(contextString ‖ "msg" ‖ msg)` → 64 bytes.
pub fn h4(msg: &[u8]) -> [u8; 64] {
    sha512(&[CONTEXT_STRING, H4_LABEL, msg])
}

/// RFC 9591 §6.1 H5: commitment-list hash `H(contextString ‖ "com" ‖ encoded)` → 64 bytes.
pub fn h5(encoded: &[u8]) -> [u8; 64] {
    sha512(&[CONTEXT_STRING, H5_LABEL, encoded])
}

/// RFC 9591 §4.3 `encode_group_commitment_list`: the `(identifier, D_i, E_i)`
/// list **sorted by identifier (ascending)**, each entry encoded length-exactly
/// as `id_enc(32) ‖ D_enc(32) ‖ E_enc(32)`. Verified against
/// `frost-core-2.2.0/src/round1.rs:392-404`, which iterates a `BTreeMap` keyed
/// by `Identifier` (ascending) and serializes `id ‖ hiding ‖ binding`. The sort
/// and the length-exact encoding are where one-byte deviations hide.
pub fn encode_commitment_list(commitments: &[SigningCommitments]) -> Vec<u8> {
    let mut sorted: Vec<&SigningCommitments> = commitments.iter().collect();
    sorted.sort_by_key(|c| c.id);
    let mut out = Vec::with_capacity(sorted.len() * 96);
    for c in sorted {
        out.extend_from_slice(&c.id.as_scalar().to_bytes());
        out.extend_from_slice(&c.hiding.to_compressed());
        out.extend_from_slice(&c.binding.to_compressed());
    }
    out
}
