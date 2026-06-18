//! # legacy
//!
//! The naive single-key Schnorr scheme the repo used to ship, reduced to its core
//! math (kickoff-amendment-1 §1, phase1-spec §8). This crate is the **Phase 3 ROS
//! attack target**: it is built and smoke-tested here, then attacked by the
//! polynomial-time ROS solver and `tests/ros_resistance.rs` in Phase 3.
//!
//! It is a separate workspace member and is **not** a dependency of `frost-core`
//! — the secure scheme and its naive predecessor never share a graph.
//!
//! `unsafe` is forbidden crate-wide (workspace lint + the crate attribute below).

#![forbid(unsafe_code)]

pub mod oracle;

pub use oracle::{NaiveSchnorrOracle, SessionId, verify};
