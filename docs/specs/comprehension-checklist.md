# frost-ed25519-kit — Owner's Comprehension Self-Exam

**This file holds questions, not answers — by design.**

The distribution gate (NORTH-STAR §4, DoD item 11) is *re-derivation from memory*.
Answer every question below **unaided**: no source, no test, no reference
implementation, no notes, and not this repo's own prose. An answer key would defeat
the gate — memorizing it is not the same as owning the layer — so none is written
here.

The pass condition is not "I could look it up." It is: **you can derive each of these
from scratch, on a whiteboard, with nothing open.** If any one cannot be derived
unaided, the gate is **not** cleared — that is the signal this layer is not yet owned,
and it must be closed before the next repo or the flagship builds on it. Distribution
waits on this; it is owner-only and no automated session can mark it done.

---

## The questions

1. **Derive the FROST partial signature `z_i` from scratch.** Write it out. What is
   each term, and why is it there? Account for the nonce pair, the binding factor, the
   Lagrange coefficient, the challenge, and the share.

2. **Why does the binding factor defeat the ROS attack?** Construct the ROS solver's
   linear system against the *naive* concurrent-Schnorr scheme — show the challenges
   as a solvable linear combination the attacker pre-commits to. Then show why that
   system has **no analogue** under FROST: what specifically stops the solver once the
   per-session commitment depends on the binding factor?

3. **What exactly does the DKG proof of knowledge prove, and which attack does it
   stop?** Write the verification equation. Then describe a rogue-key / biasing attack
   it prevents, and show why an attacker without the matching secret cannot produce a
   passing proof.

4. **Why is reconstruction from `t-1` shares information-theoretically impossible, and
   what changes at `t`?** State the argument in terms of polynomial interpolation and
   the space of consistent constant terms — and be precise about why this is *not*
   "computationally hard" but *nothing*.

5. **Why is strict canonical-encoding enforcement necessary?** What malleability does
   accepting a non-canonical encoding permit — construct the two-byte-strings-one-point
   case concretely (which byte, which values). How did the coverage-guided fuzzer find
   it where the random-input floor did not, and why?

6. **What can a malicious aggregator do, and what can it provably *not* do?** Separate
   liveness from safety. Show why it cannot solve for a share from the partials it
   sees, and what identifiable abort bounds it to.

7. **What is the DKG's transport trust assumption, and why does VSS force it?** Which
   message carries a secret, why must it, and what breaks if it crosses a channel that
   is not private and authenticated?

---

*Answered from memory, unaided. This file is intentionally answer-free.*
