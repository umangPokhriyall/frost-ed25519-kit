# Solana MPC Kit

> Threshold cryptography and multi-party computation (MPC) infrastructure for secure Solana key management.  
> Open-source, Rust-based, self-hostable.

---

## ✨ Overview

**Solana MPC Kit** is a Rust project implementing **distributed key generation (DKG)** and **threshold signing** for Solana.  
It allows companies and developers to create wallets without ever exposing a full private key, instead distributing shares across independent nodes.

Inspired by institutional setups (like exchanges and custodians), this kit enables:

- **t-of-n threshold signing** (e.g. 3-of-5)  
- **Decentralized key generation (DKG)** using Feldman-style verifiable secret sharing  
- **Secure local share storage** on each node  
- **Orchestrator service** that coordinates wallet creation & signing  
- **Node agents** that never reveal their share, only partial results  
- **Aggregate public key generation** compatible with Solana transactions  

---

## 🏗 Architecture

- **Orchestrator**  
  - Exposes REST API for clients  
  - Manages sessions (wallet creation, signing)  
  - Collects commitments, verifies shares, aggregates public key  
  - Combines partial signatures into final Solana-compatible signature  

- **Node Agent**  
  - Participates in DKG rounds (polynomial commitments, shares)  
  - Verifies commitments from peers  
  - Stores final key share locally (encrypted)  
  - Responds with partial signatures during signing  

- **Dependencies**  
  - [poem](https://github.com/poem-web/poem) – web framework  
  - [diesel](https://diesel.rs/) – Postgres ORM (planned)  
  - [tokio](https://tokio.rs/) – async runtime  
  - [redis](https://redis.io/) – message bus (planned)  
  - [k256](https://docs.rs/k256) – elliptic curve (secp256k1/ed25519) ops  
  - [serde](https://serde.rs/) – serialization  
  - [tracing](https://docs.rs/tracing) – logging  

---

## 🔑 Features (current & roadmap)

- ✅ Distributed Key Generation (Round 1 + Round 2)  
- ✅ Aggregate public key calculation  
- 🔜 Secure local share storage (AES-GCM encrypted)  
- 🔜 Threshold signing with nonce commitments & partial signatures  
- 🔜 Redis-based async orchestration  
- 🔜 Integration with Solana transactions (`solana-sdk`)  

---

## 🚀 Getting Started

### Run Orchestrator
```bash
cd orchestrator
cargo run
```

### Run Node Agents
```bash
cd node
cargo run -- --port 4001
cargo run -- --port 4002
```

## Create Wallet (2-of-2 example)

```bash
curl -X POST http://127.0.0.1:3000/wallets \
  -H "Content-Type: application/json" \
  -d '{"threshold":2,"participants":2}'
```

### Example Response:
```bash
{
  "wallet_id": "61bb1cdf-1e80-4adf-94c4-487a5df93859",
  "aggregate_pubkey": "04eac28990..."
}

```

## 🛣 Roadmap
- Add secure encrypted share storage per node

- Implement t-of-n threshold signing (FROST/MuSig2 style)

- Add Postgres schema for sessions & audit logs

- Use Redis streams for orchestrator <-> node communication

- Full Solana transaction signing & broadcasting