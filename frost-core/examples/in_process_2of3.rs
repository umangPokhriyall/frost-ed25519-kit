//! In-process 3-party FROST(Ed25519): a no-dealer Pedersen DKG followed by a
//! 2-of-3 threshold signature, verified under RFC 8032. Every protocol message
//! crosses an `std::sync::mpsc` channel — never a direct function call — so the
//! sans-IO boundary is visible and the run reads as a real multi-party exchange.
//! No file or network I/O; the only output is stdout (phase4-spec §4).
//!
//! Run: `cargo run --example in_process_2of3`

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use frost_core::dkg::{self, round1, round2};
use frost_core::group::Identifier;
use frost_core::keygen::{KeyPackage, PublicKeyPackage};
use frost_core::{sign, verify};
use rand::rngs::OsRng;

/// Per-participant transport: the two round inboxes this participant reads, and
/// the broadcast senders keyed by recipient. The frozen `dkg::part1/2/3` never
/// see any of it — the caller owns the channels (the sans-IO boundary).
struct Mailbox {
    rx1: Receiver<(Identifier, round1::Package)>,
    rx2: Receiver<(Identifier, round2::Package)>,
    r1_tx: BTreeMap<Identifier, Sender<(Identifier, round1::Package)>>,
    r2_tx: BTreeMap<Identifier, Sender<(Identifier, round2::Package)>>,
}

/// One participant: runs the three DKG rounds, exchanging packages only over the
/// channels. Returns this participant's long-lived key material.
fn participant(
    id: Identifier,
    t: u16,
    n: u16,
    peers: Vec<Identifier>,
    mail: Mailbox,
) -> (KeyPackage, PublicKeyPackage) {
    let mut rng = OsRng;

    // Round 1: commit to a degree-(t-1) polynomial + prove knowledge of its
    // constant term; broadcast the public package to every peer.
    let (secret1, package1) = dkg::part1(id, t, n, &mut rng).unwrap();
    for &peer in &peers {
        mail.r1_tx[&peer].send((id, package1.clone())).unwrap();
    }
    let mut round1_packages = BTreeMap::new();
    for _ in &peers {
        let (sender, pkg) = mail.rx1.recv().unwrap();
        round1_packages.insert(sender, pkg);
    }

    // Round 2: verify every peer's PoK, then emit one private share per
    // recipient over its (assumed private, authenticated) channel.
    let (secret2, outgoing) = dkg::part2(secret1, &round1_packages).unwrap();
    for (recipient, pkg) in outgoing {
        mail.r2_tx[&recipient].send((id, pkg)).unwrap();
    }
    let mut round2_packages = BTreeMap::new();
    for _ in &peers {
        let (sender, pkg) = mail.rx2.recv().unwrap();
        round2_packages.insert(sender, pkg);
    }

    // Round 3: verify each received share against its dealer's commitment, sum to
    // the signing share, derive the group key + verifying shares.
    dkg::part3(&secret2, &round1_packages, &round2_packages).unwrap()
}

fn main() {
    let (t, n): (u16, u16) = (2, 3);
    let ids: Vec<Identifier> = (1..=n as u64)
        .map(|i| Identifier::try_from_u64(i).unwrap())
        .collect();

    // One inbox per participant per DKG round; messages carry the sender id.
    let mut r1_tx = BTreeMap::new();
    let mut r1_rx = BTreeMap::new();
    let mut r2_tx = BTreeMap::new();
    let mut r2_rx = BTreeMap::new();
    for &id in &ids {
        let (tx1, rx1) = channel::<(Identifier, round1::Package)>();
        let (tx2, rx2) = channel::<(Identifier, round2::Package)>();
        r1_tx.insert(id, tx1);
        r1_rx.insert(id, rx1);
        r2_tx.insert(id, tx2);
        r2_rx.insert(id, rx2);
    }

    // Each participant runs concurrently; the DKG completes only by message passing.
    let results: Vec<(KeyPackage, PublicKeyPackage)> = thread::scope(|scope| {
        let mut handles = Vec::new();
        for &id in &ids {
            let mail = Mailbox {
                rx1: r1_rx.remove(&id).unwrap(),
                rx2: r2_rx.remove(&id).unwrap(),
                r1_tx: r1_tx.clone(),
                r2_tx: r2_tx.clone(),
            };
            let peers: Vec<Identifier> = ids.iter().copied().filter(|&p| p != id).collect();
            handles.push(scope.spawn(move || participant(id, t, n, peers, mail)));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // All participants derive the same PublicKeyPackage; key the signing shares by id.
    let public = &results[0].1;
    let key_packages: BTreeMap<Identifier, &KeyPackage> =
        results.iter().map(|(kp, _)| (kp.id, kp)).collect();

    // Choose a 2-of-3 signer set and run FROST commit -> sign -> aggregate.
    let signer_ids = [ids[0], ids[1]];
    let msg = b"frost-ed25519-kit in-process 2-of-3 demo";
    let mut rng = OsRng;

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
        shares.push(sign::sign(share, nce, id, &commitments, public, msg).unwrap());
    }
    let sig = sign::aggregate(&shares, &commitments, public, msg).unwrap();
    verify::verify(&public.group_public, msg, &sig).unwrap();

    let group_hex: String = public
        .group_public
        .to_compressed()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("Pedersen DKG complete: {n} participants, no dealer held the key");
    println!("group public key: {group_hex}");
    println!("2-of-3 signature ({} bytes) accepted by RFC 8032 verify", sig.to_bytes().len());
    println!("verified");
}
