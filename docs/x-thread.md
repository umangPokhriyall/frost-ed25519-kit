# Distribution thread — frost-ed25519-kit

Findings-first (NORTH-STAR §7). Every claim cites a committed file; no adjective a
number has not earned; no ask. Reviewed against the repo before posting.

---

**1/**
I shipped a "threshold MPC" Solana signer, then audited my own code. The
coordinator held the whole key, and the signing scheme was forgeable. So I forged
it on purpose: a valid signature on a message no honest session ever signed, in
~49 ms.
(`legacy/results/ros_forgery.txt`)

**2/**
The audit findings, plainly. The coordinator could reconstruct the full secret —
that is not threshold signing, it is a key held in one place with extra steps. The
signing scheme was a naive concurrent Schnorr. The DKG shares were handled in the
clear.

**3/**
Naive concurrent Schnorr is broken by the ROS attack (Benhamouda–Lepoint–Loss–
Orrù–Raykova 2020): open ℓ concurrent sessions, treat their challenges as a linear
system, and solve for a forgery on an unsigned message. I ran it against the old
scheme: 256 sessions, forgery in ~49 ms. (`legacy/results/ros_forgery.txt`,
`frost-core/tests/ros_resistance.rs`)

**4/**
The rebuild: hand-rolled FROST(Ed25519, SHA-512) per RFC 9591. It is checked, not
asserted — byte-for-byte against the official RFC 9591 vectors, intermediates
first (binding factors, group commitment, each partial, final signature), so the
first diverging step is named. (`frost-core/tests/rfc9591_kat.rs`)

**5/**
Beyond the fixed vectors: a ≥10,000-case differential against the independent
`frost-ed25519` crate over `2 ≤ t ≤ n ≤ 8`, random subsets and messages. The
reference crate is a dev-only oracle, never in the shipped graph.
(`frost-core/tests/differential.rs`)

**6/**
No trusted dealer. A Pedersen DKG where no party ever holds the group secret, with
a Schnorr proof of knowledge of each participant's polynomial constant term — the
rogue-key defense, so a participant cannot choose its contribution as a function of
others'. (`frost-core/src/dkg.rs`, `frost-core/tests/dkg_pok_pin.rs`)

**7/**
Why FROST resists what the old scheme did not. Each signer's nonce is bound by
`ρ_i = H1(group_public ‖ msg ‖ commitment_list ‖ id)`. The challenge is no longer
linear in quantities the attacker controls before committing, so the ROS solver
has no linear system to solve. The same solver returns `RosOutcome::NoSolution`
against FROST. (`frost-core/tests/ros_resistance.rs`, `docs/THREAT-MODEL.md` §4)

**8/**
The surface. `#![forbid(unsafe_code)]` crate-wide, sans-IO (no network, no
database, no `solana-*` in the crypto path), six shipped dependencies
(`cargo tree -e normal`). Secrets are zeroized after use and nonces are hedged
`H3(random ‖ encode(secret))`. (`docs/ARCHITECTURE.md`, `frost-core/src/secret.rs`)

**9/**
Repo and threat model below. The DKG private-channel assumption and the
abort-and-identify (non-robust) property are stated up front.
github.com/umangPokhriyall/frost-ed25519-kit — `docs/THREAT-MODEL.md`
