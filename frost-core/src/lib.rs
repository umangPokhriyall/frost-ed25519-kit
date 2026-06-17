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
//! Modules are landed across Phase 0 sessions; this scaffold (Session 0.1) is
//! the workspace skeleton only.
//!
//! - `group`   — validated, constant-time scalar/point/identifier layer. FROZEN after P0.
//! - `secret`  — Zeroizing secret types, single-use nonces. FROZEN after P0.
//! - `error`   — the crate error enum (includes `Culprit`, defined now for P1).
//! - `message` — transport-agnostic wire types. FROZEN after P0.
//! - `vss`     — Feldman commitments + verification. FROZEN after P0.
//! - `keygen`  — trusted-dealer keygen (+ public verifying shares); Pedersen DKG in P2.

#![forbid(unsafe_code)]
