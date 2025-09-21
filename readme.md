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
  - Coordinates DKG rounds (collects commitments, verifies shares)
  - Stores sessions in Postgres (wallets, signing sessions, audit logs) 
  - Aggregates the final public key  
  - Combines partial signatures into a valid Solana signature
  - Broadcasts signed transactions to devnet

- **Node Agent**  
  - Participates in DKG rounds (polynomial commitments, shares)  
  - Verifies commitments from peers  
  - Stores final key share locally (encrypted)  
  - Responds with partial signatures during signing  
  - Never reveals its secret share

- **Dependencies**  
  - [poem](https://github.com/poem-web/poem) – web framework  
  - [diesel](https://diesel.rs/) – Postgres ORM (planned)  
  - [tokio](https://tokio.rs/) – async runtime  
  - [redis](https://redis.io/) – message bus (planned)  
  - [curve25519-dalek](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/) – Ed25519 curve math
  - [serde](https://serde.rs/) – serialization  
  - [tracing](https://docs.rs/tracing) – logging  

---

## 🔑 Features

### ✅Current

- Distributed Key Generation (Round 1 + Round 2)  
- Aggregate public key calculation  
- Native SOL transfer via threshold signing 
- SPL token transfer support 
- Persistence with Postgres

## 🔜 Roadmap

- Encrypted local share storage (AES-GCM per node)
- Threshold signing with nonce commitments (FROST-style)
- Key share refresh protocol
- Redis-based async orchestration 
- Public API keys for external integrations
- Full audit logs

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
## Send SOL

```bash
curl -X POST http://127.0.0.1:3000/wallets/<WALLET_ID>/send \
  -H "Content-Type: application/json" \
  -d '{"to":"<RECIPIENT_PUBKEY>", "amount":1000000}'
```

### Example Response:
```bash
{
  "signature": "4EeD7bD8pNWhW5qoJkxjFvtkomWxJPdXEpR54ZmCJgWNTG2NqDi8.....k"  
}

```
## Send Token

```bash
curl -X POST http://127.0.0.1:3000/wallets/<WALLET_ID>/send \
  -H "Content-Type: application/json" \
  -d '{"to":"<RECIPIENT_PUBKEY>", "amount":1000000, "token": "<TOKEN_NAME>", "mint":"<MINT_ADDRESS>"}'
```

### Example Response:
```bash
{
  "signature": "4EeD7bD8pNWhW5qoJkxjFvtkomWxJPdXEpR54ZmCJgWNTG2NqDi8.....k"  
}

```
## Sign Transaction

```bash
curl -X POST http://127.0.0.1:3000/wallets/<WALLET_ID>/sign \
  -H "Content-Type: application/json" \
  -d '{"message":"<TRANSACTION_HEX>"}'
```

### Example Response:
```bash
{
  "signature": "4EeD7bD8pNWhW5qoJkxjFvtkomWxJPdXEpR54ZmCJgWNTG2NqDi8.....k"  
}

```

## ⚠️ Disclaimer

This is an MPC prototype.
It demonstrates the core flow of distributed keygen, signing, and transaction broadcasting. Not production ready.