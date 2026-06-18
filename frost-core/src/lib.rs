//! # frost-core
//!
//! Sans-IO foundation for FROST(Ed25519). The trust-critical path performs no
//! I/O: there is no `tokio`, `reqwest`, `diesel`, Postgres, or `solana-*` here,
//! and there never will be (phase0-spec §1.1). Callers drive the protocol and
//! own all transport.
//!
//! `unsafe` is forbidden crate-wide (see the crate attribute below and the
//! `unsafe_code = "forbid"` workspace lint).
//!
//! ## Module map (phase0-spec §2.2)
//!
//! - `group`   — validated, constant-time scalar/point/identifier layer. FROZEN after P0.
//! - `secret`  — Zeroizing secret types, single-use nonces. FROZEN after P0.
//! - `error`   — the crate error enum (includes `Culprit`, defined now for P1).
//! - `vss`     — Feldman commitments + verification. FROZEN after P0.
//! - `keygen`  — trusted-dealer keygen (+ public verifying shares); retained as the P2 fallback.
//! - `dkg`     — Pedersen verifiable DKG (P2): part1/part2/part3, rogue-key PoK, identifiable abort.
//! - `ciphersuite` — FROST(Ed25519, SHA-512) constants + H1–H5 (phase1-spec §3).
//! - `sign`    — round 1 `commit` (hedged), round 2 `sign`, `aggregate` (identifiable abort).
//! - `verify`  — RFC 8032 aggregate `verify` + per-partial `verify_share`.
//!
//! `message` (transport-agnostic wire types) is reserved for when Phase 1 first
//! needs a wire type; it carries no Phase 0 content and freezes on introduction.

#![forbid(unsafe_code)]

pub mod ciphersuite;
pub mod dkg;
pub mod error;
pub mod group;
pub mod keygen;
pub mod secret;
pub mod sign;
pub mod verify;
pub mod vss;

pub use error::Error;
pub use keygen::{KeyPackage, PublicKeyPackage, trusted_dealer_keygen};
// Note: the `sign::sign` and `verify::verify` functions are reached module-qualified
// (`sign::sign`, `verify::verify`); they are not re-exported here because each name
// would collide with its module at the crate root. The value types are re-exported.
pub use sign::{Signature, SignatureShare, SigningCommitments};
