//! Offline interop proof (phase4-spec §5): a FROST(Ed25519) threshold signature
//! is a standard RFC 8032 Ed25519 signature, accepted by an INDEPENDENT verifier
//! (`ed25519-dalek` — a different implementation than our `verify.rs` and than the
//! `frost-ed25519` differential oracle), and the group public key is a valid
//! Solana address (base58 of the 32-byte Ed25519 key).
//!
//! There is no Solana SDK, no RPC, and no broadcast here — see the proven/not-done
//! block at the end of `main`. This earns the "Ed25519 / Solana-compatible" claim
//! by independent verification alone.
//!
//! Run: `cargo run --example solana_compat`

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use frost_core::group::Identifier;
use frost_core::keygen::trusted_dealer_keygen;
use frost_core::{sign, verify};
use rand::rngs::OsRng;

fn main() {
    let mut rng = OsRng;

    // 1. Keygen (trusted dealer here; the DKG path is in in_process_2of3) and a
    //    2-of-3 FROST signature over a fixed message.
    let (t, n) = (2u16, 3u64);
    let ids: Vec<Identifier> = (1..=n).map(|i| Identifier::try_from_u64(i).unwrap()).collect();
    let (key_packages, public) = trusted_dealer_keygen(t, &ids, &mut rng).unwrap();

    let msg = b"frost-ed25519-kit: a FROST signature is a standard Ed25519 signature";
    let signer_ids = [ids[0], ids[1]];

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &id in &signer_ids {
        let (nce, com) = sign::commit(id, &key_packages[&id].signing_share, &mut rng);
        nonces.push(nce);
        commitments.push(com);
    }
    let mut shares = Vec::new();
    for (&id, nce) in signer_ids.iter().zip(nonces) {
        let share = &key_packages[&id].signing_share;
        shares.push(sign::sign(share, nce, id, &commitments, &public, msg).unwrap());
    }
    let sig = sign::aggregate(&shares, &commitments, &public, msg).unwrap();

    // Our own RFC 8032 verifier accepts it (the cofactored check in verify.rs).
    verify::verify(&public.group_public, msg, &sig).unwrap();

    // 2. Independent verification: hand the 32-byte group key and the 64-byte
    //    signature to `ed25519-dalek`, an entirely separate implementation.
    let group_public_bytes: [u8; 32] = public.group_public.to_compressed();
    let sig_bytes: [u8; 64] = sig.to_bytes();
    let vk = VerifyingKey::from_bytes(&group_public_bytes)
        .expect("group public key is a canonical, non-small-order Ed25519 point");
    let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

    // Verify-never-assume (phase4-spec §5): measure which dalek variant accepts the
    // signature rather than assuming. `verify_strict` is the stricter check
    // (cofactorless equation; rejects non-canonical / small-order R and A);
    // `verify` (the `Verifier` trait) is the cofactored RFC 8032 check.
    let strict_ok = vk.verify_strict(msg, &dalek_sig).is_ok();
    let cofactored_ok = vk.verify(msg, &dalek_sig).is_ok();

    // An honestly generated FROST R is torsion-free and canonical, so it is
    // expected to pass the strict check — confirmed here, not assumed. Require it.
    assert!(strict_ok, "ed25519-dalek verify_strict rejected the FROST signature");
    assert!(cofactored_ok, "ed25519-dalek cofactored verify rejected the FROST signature");

    // 3. The Solana address is the base58 of the 32-byte Ed25519 public key.
    let solana_address = bs58::encode(group_public_bytes).into_string();

    println!("message: {:?}", std::str::from_utf8(msg).unwrap());
    println!("independent verifier: ed25519-dalek v2");
    println!("  verify_strict (cofactorless): {}", if strict_ok { "accepted" } else { "rejected" });
    println!("  verify        (cofactored):   {}", if cofactored_ok { "accepted" } else { "rejected" });
    println!("documented call: VerifyingKey::verify_strict — the accepting variant");
    println!("Solana address (base58 of the group key): {solana_address}");

    // ---------------------------------------------------------------------------
    // What this proves, and what it does not (phase4-spec §5):
    //
    //   PROVEN
    //     - The threshold signature is a standard RFC 8032 Ed25519 signature: an
    //       INDEPENDENT verifier (ed25519-dalek, a different implementation than
    //       frost-core's verify.rs and than the frost-ed25519 differential oracle)
    //       accepts it under verify_strict — so any standard Ed25519 verifier does.
    //     - The group public key is a valid Solana address: a normal Ed25519
    //       public key IS a Solana address, printed above as its base58 encoding.
    //
    //   NOT DONE (deliberately — this is an offline interop proof)
    //     - No broadcast, no RPC, no Solana SDK, no on-chain transaction.
    //     - No System Program transfer or any account is constructed or sent.
    //
    // The claim is interoperability of the signature and the key format, proven
    // offline by an independent verifier — nothing about a live chain.
    // ---------------------------------------------------------------------------
}
