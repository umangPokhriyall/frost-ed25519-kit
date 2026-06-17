//! The crate error model (phase0-spec §5).
//!
//! Every fallible operation in `frost-core` returns `Result<_, Error>`. No
//! public API panics, unwraps, or expects on caller- or peer-controlled input.
//! Several variants (`InvalidShare`, `Culprit`, `InvalidSignature`,
//! `InvalidThreshold`) are defined now and first constructed in later phases;
//! they are part of the contract from Phase 0 on.

use crate::group::Identifier;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("non-canonical scalar encoding")]
    NonCanonicalScalar,
    #[error("point not in prime-order subgroup")]
    NonPrimeOrderPoint,
    #[error("invalid point encoding")]
    InvalidPointEncoding,
    #[error("zero identifier")]
    ZeroIdentifier,
    #[error("duplicate identifier")]
    DuplicateIdentifier,
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error("share failed Feldman verification for dealer {0:?}")]
    InvalidShare(Identifier),
    #[error("threshold > participants")]
    InvalidThreshold,
    // Defined now, first used in Phase 1:
    #[error("partial signature invalid; culprit {0:?}")]
    Culprit(Identifier),
    #[error("aggregate signature failed verification")]
    InvalidSignature,
}
