//! Stable bounded harness (phase3-spec §5 — honesty: measure, never guess).
//!
//! Runs each deserializer invariant check over a deterministic corpus — fixed edge
//! seeds plus a seeded-PRNG stream — on the **stable** toolchain, with no libFuzzer
//! linkage. It is the executable proof that the invariants hold over the committed
//! budget; the exec count printed here is what `README.md` reports (as "N execs, 0
//! crashes", not "clean"). The coverage-guided libFuzzer targets are the exhaustive
//! local version (`cargo +nightly fuzz run --features libfuzzer <target>`).
//!
//! A panic in any `check_*` (an accepted non-canonical encoding, a non-prime-order
//! point, or an out-of-bounds index) fails this test.

use frost_core_fuzz::{
    check_gelement, check_gscalar, check_identifier, check_round2_package, check_signature,
    check_signing_share,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Random inputs per target. 200k × 6 targets = 1.2M execs — a few seconds on
/// stable, fast enough for the workspace-adjacent run while still a meaningful
/// bounded budget. Longer runs are the libFuzzer job.
const RANDOM_ITERS: usize = 200_000;

/// Run `check` over edge seeds and `RANDOM_ITERS` PRNG draws of `width` bytes
/// (plus a few off-width lengths to exercise the length guards). Returns the exec
/// count. Each input length brackets `width` so both the "too short → early return"
/// and the "exact length" paths are hit.
fn drive(seed: u64, width: usize, check: impl Fn(&[u8])) -> usize {
    let mut execs = 0usize;

    // Fixed edge seeds: empty, short, all-zero, all-0xFF, low-bit-set — the
    // classic boundary encodings (zero scalar/identifier, max value, etc.).
    let edges: [Vec<u8>; 6] = [
        vec![],
        vec![0u8; width.saturating_sub(1)],
        vec![0u8; width],
        vec![0xffu8; width],
        {
            let mut v = vec![0u8; width];
            if !v.is_empty() {
                v[0] = 1;
            }
            v
        },
        vec![0u8; width + 1],
    ];
    for e in &edges {
        check(e);
        execs += 1;
    }

    // Seeded PRNG stream at the exact width and one byte either side.
    let mut rng = StdRng::seed_from_u64(seed);
    for width in [width.saturating_sub(1), width, width + 1] {
        let mut buf = vec![0u8; width];
        for _ in 0..RANDOM_ITERS {
            rng.fill_bytes(&mut buf);
            check(&buf);
            execs += 1;
        }
    }
    execs
}

#[test]
fn bounded_pass_no_crashes() {
    // Distinct seeds so the six streams do not coincide.
    let total = drive(0xA001, 32, check_gscalar)
        + drive(0xA002, 32, check_gelement)
        + drive(0xA003, 32, check_identifier)
        + drive(0xA004, 32, check_signing_share)
        + drive(0xA005, 64, check_signature)
        + drive(0xA006, 64, check_round2_package);

    // Surfaced in `cargo test -- --nocapture` and recorded in README.md.
    println!("fuzz bounded pass: {total} execs across 6 targets, 0 crashes");
    assert!(total >= 6 * 3 * RANDOM_ITERS, "bounded budget must run in full");
}
