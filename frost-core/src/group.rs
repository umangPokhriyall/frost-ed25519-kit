//! Validated, constant-time group layer (phase0-spec §3). FROZEN after P0.
//!
//! This module wraps `curve25519-dalek` so that **every value crossing the
//! trust boundary is validated on construction**: scalars are rejected unless
//! canonically encoded (never reduced mod L), points are rejected unless they
//! are torsion-free (cofactor-clean), and identifiers are rejected unless they
//! are nonzero. Raw `Scalar` / `EdwardsPoint` never appear in the public APIs
//! of higher modules — this is the only place those types are touched.

use core::cmp::Ordering;
use core::ops::{Add, Mul, Sub};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use subtle::ConstantTimeEq;

use crate::error::Error;

/// A canonical scalar in `[0, L)`. Constructed only via validated decoding.
#[derive(Clone, Copy)]
pub struct GScalar(Scalar);

impl GScalar {
    /// Decode a canonical scalar. Rejects non-canonical encodings — NEVER
    /// reduces mod L (amendment: reject, never coerce).
    pub fn from_canonical_bytes(b: [u8; 32]) -> Result<Self, Error> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(b))
            .map(GScalar)
            .ok_or(Error::NonCanonicalScalar)
    }

    /// The canonical 32-byte little-endian encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Multiplicative inverse (constant-time, via dalek).
    pub fn invert(&self) -> Self {
        GScalar(self.0.invert())
    }

    /// Access the wrapped dalek scalar. Crate-internal: keeps raw `Scalar` out
    /// of higher modules' public APIs.
    pub(crate) fn as_scalar(&self) -> Scalar {
        self.0
    }
}

// Arithmetic delegates to dalek (constant-time). Implemented as std ops traits
// rather than inherent `add`/`sub`/`mul` methods (clippy::should_implement_trait).
impl Add for GScalar {
    type Output = GScalar;
    fn add(self, rhs: Self) -> Self {
        GScalar(self.0 + rhs.0)
    }
}
impl Sub for GScalar {
    type Output = GScalar;
    fn sub(self, rhs: Self) -> Self {
        GScalar(self.0 - rhs.0)
    }
}
impl Mul for GScalar {
    type Output = GScalar;
    fn mul(self, rhs: Self) -> Self {
        GScalar(self.0 * rhs.0)
    }
}

// Constant-time equality (subtle): inputs may be secret-derived.
impl PartialEq for GScalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for GScalar {}

/// A point validated to be in the prime-order subgroup (cofactor-clean).
#[derive(Clone, Copy)]
pub struct GElement(EdwardsPoint);

impl GElement {
    /// Decompress, then REJECT if not torsion-free (small-subgroup / cofactor
    /// attack guard). Non-decompressable bytes are `InvalidPointEncoding`;
    /// decompressable-but-not-torsion-free points are `NonPrimeOrderPoint`.
    pub fn from_compressed(b: [u8; 32]) -> Result<Self, Error> {
        let point = CompressedEdwardsY(b)
            .decompress()
            .ok_or(Error::InvalidPointEncoding)?;
        if point.is_torsion_free() {
            Ok(GElement(point))
        } else {
            Err(Error::NonPrimeOrderPoint)
        }
    }

    /// The canonical 32-byte compressed (Edwards y + sign) encoding.
    pub fn to_compressed(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// The Ed25519 base point.
    pub fn generator() -> Self {
        GElement(ED25519_BASEPOINT_POINT)
    }

    /// Scalar multiplication (constant-time, via dalek).
    pub fn scalar_mul(&self, s: &GScalar) -> Self {
        GElement(self.0 * s.0)
    }
}

impl Add for GElement {
    type Output = GElement;
    fn add(self, rhs: Self) -> Self {
        GElement(self.0 + rhs.0)
    }
}

impl PartialEq for GElement {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Eq for GElement {}

/// A participant identifier: a NONZERO scalar (amendment §5). `x = 0` is the
/// secret's own coordinate and is rejected at construction; ordering and
/// equality treat identifiers as public values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Identifier(GScalar);

impl Identifier {
    /// Decode a nonzero canonical scalar. Zero (a canonical encoding) is
    /// `Err(ZeroIdentifier)`; a non-canonical encoding is `Err(NonCanonicalScalar)`.
    pub fn from_canonical_bytes(b: [u8; 32]) -> Result<Self, Error> {
        let scalar = GScalar::from_canonical_bytes(b)?;
        if bool::from(scalar.0.ct_eq(&Scalar::ZERO)) {
            return Err(Error::ZeroIdentifier);
        }
        Ok(Identifier(scalar))
    }

    /// Convenience for small integer ids used in keygen/tests. `0` is
    /// `Err(ZeroIdentifier)`.
    pub fn try_from_u64(x: u64) -> Result<Self, Error> {
        if x == 0 {
            return Err(Error::ZeroIdentifier);
        }
        Ok(Identifier(GScalar(Scalar::from(x))))
    }

    /// The underlying nonzero scalar.
    pub fn as_scalar(&self) -> GScalar {
        self.0
    }
}

// Identifiers are public values; order them by canonical encoding so they can
// key a `BTreeMap` (keygen). Consistent with `Eq`: equal encoding <=> equal id.
impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_bytes().cmp(&other.0.to_bytes())
    }
}

impl core::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Identifier(0x")?;
        for byte in self.0.to_bytes() {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(")")
    }
}

/// Validate that a set of identifiers contains no duplicates (amendment §5).
/// Duplicates make a Lagrange denominator `(x_i − x_j) = 0`.
pub fn validate_identifier_set(ids: &[Identifier]) -> Result<(), Error> {
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            return Err(Error::DuplicateIdentifier);
        }
    }
    Ok(())
}
