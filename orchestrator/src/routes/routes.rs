// orchestrator/src/routes.rs
use poem::{handler, web::Json, web::Path, web::Data};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use reqwest::Client;
use bs58;
use bincode;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hex;
use anyhow::Result;
use store::module::*;
use std::sync::{Arc, Mutex};
use store::store::Store;

use std::convert::TryInto;
use sha2::{Sha512, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::IsIdentity; // not strictly needed
use std::str::FromStr;


use solana_sdk::{
    pubkey::Pubkey,
    system_instruction,
    transaction::Transaction,
    message::Message,
    signature::Signature,
    hash::Hash,
};
use solana_client::rpc_client::RpcClient;
use base64::{engine::general_purpose, Engine as _};

use solana_sdk::instruction::Instruction;
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account_idempotent,
};
use spl_token::instruction::transfer_checked;
use spl_token::ID as TOKEN_PROGRAM_ID;




#[derive(Deserialize)]
pub struct CreateWalletRequest {
    pub threshold: usize,
    pub participants: usize,
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub wallet_id: Uuid,
    pub aggregate_pubkey: String, // hex of compressed Edwards Y (32 bytes)
}

#[derive(Deserialize, Serialize, Clone)]
pub struct Round1Response {
    pub wallet_id: String,               
    pub commitments: Vec<String>,        // hex-encoded compressed Edwards Y (C0..Ct-1)
    pub shares: Vec<(u64, String)>,      // (recipient index, share hex)
}

#[derive(Deserialize, Serialize)]
pub struct Round2Request {
    pub all_round1: Vec<Round1Response>,
    pub my_index: u64,
}

#[derive(Deserialize, Serialize)]
pub struct Round2Response {
    pub ack: bool,
    pub failing_dealer: Option<usize>,
    pub my_final_share: Option<String>,
}

pub fn node_endpoints() -> Vec<&'static str> {
    vec![
        "http://127.0.0.1:4001",
        "http://127.0.0.1:4002"
    ]
}

#[handler]
pub async fn create_wallet(Json(req): Json<CreateWalletRequest>, Data(store): Data<&Arc<Mutex<Store>>>) -> Json<CreateWalletResponse> {
    let wallet_id = Uuid::new_v4();
    let client = Client::new();

    // --- Round 1: ask each node for their commitments/shares ---
    let mut round1_responses: Vec<Round1Response> = Vec::new();

    for node in node_endpoints() {
        let url = format!("{}/dkg/round1/start", node);
        let r: Round1Response = client
            .post(&url)
            .json(&serde_json::json!({
                "wallet_id": wallet_id.to_string(),
                "threshold": req.threshold,
                "participants": req.participants
            }))
            .send()
            .await
            .expect("node round1 request failed")
            .json()
            .await
            .expect("node round1 parse failed");

        round1_responses.push(r);
    }

    // --- Round 2: distribute all Round1 to each node, collect final share ---
    let mut final_shares: Vec<(usize, String)> = Vec::new(); // (node_idx, final_share_hex)

    for (i, node) in node_endpoints().iter().enumerate() {
        let url = format!("{}/dkg/round2/verify", node);
        let req2 = Round2Request {
            all_round1: round1_responses.clone(),
            my_index: (i + 1) as u64,
        };

        let r2: Round2Response = client
            .post(&url)
            .json(&req2)
            .send()
            .await
            .expect("node round2 request failed")
            .json()
            .await
            .expect("parse r2 failed");

        if !r2.ack {
            panic!(
                "Node {} failed verification (failing dealer idx: {:?})",
                node, r2.failing_dealer
            );
        }

        if let Some(share_hex) = r2.my_final_share {
            // For PoC we collect final shares (but in production nodes must keep these private)
            final_shares.push((i, share_hex));
        } else {
            panic!("No final share from node {}", node);
        }

    }

    // --- Compute aggregate public key from constant-term commitments (C0 of each dealer)
    // X = sum_i C_{i,0}
    let mut agg_point = EdwardsPoint::identity();

    for r1 in &round1_responses {
        // parse first commitment (C0)
        let c0_hex = &r1.commitments[0];
        let bytes = hex::decode(c0_hex).expect("invalid c0 hex");
        if bytes.len() != 32 { panic!("invalid c0 length") }
        let mut arr: [u8; 32] = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let comp = CompressedEdwardsY(arr);
        let pt = comp.decompress().expect("invalid commitment point");
        agg_point = agg_point + pt;
    }

    let agg_pubkey = agg_point.compress();
    let agg_pubkey_hex = hex::encode(agg_pubkey.to_bytes());

    let mut s = store.lock().unwrap();
    let wallet_row = Wallet {
        id: wallet_id,
        pubkey: agg_pubkey_hex.clone(),
        threshold: req.threshold as i32,
        participants: req.participants as i32,
        nodes: serde_json::json!(node_endpoints()), // FIXED
        status: "active".to_string(),
    };
    s.insert_wallet(wallet_row).expect("DB insert wallet failed");

    // Also store DKG session
    let dkg_session = DkgSession {
        id: Uuid::new_v4(),
        wallet_id: Some(wallet_id), // FIXED
        round: 2,
        messages: serde_json::json!(round1_responses),
        state: "complete".to_string(),
    };
    s.insert_dkg_session(dkg_session).expect("DB insert dkg session failed");



    Json(CreateWalletResponse {
        wallet_id,
        aggregate_pubkey: bs58::encode(agg_pubkey.to_bytes()).into_string(),
    })
}

#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String, // hex/base64 transaction
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub signature: String,
}

// helper: hash (R || X || m) -> Scalar
fn challenge_scalar(R_bytes: &[u8], X_bytes: &[u8], msg: &[u8]) -> Scalar {
    // Use SHA-512 -> reduce to scalar
    let mut h = Sha512::new();
    h.update(R_bytes);
    h.update(X_bytes);
    h.update(msg);
    let digest = h.finalize();
    // take 64 bytes digest, reduce modulo curve order
    Scalar::from_bytes_mod_order_wide(&digest.as_slice().try_into().unwrap())
}

// helper: compute Lagrange coefficients for indices (Vec<u64>), return HashMap index->Scalar
fn lagrange_coeffs_at_zero(indices: &[u64]) -> std::collections::BTreeMap<u64, Scalar> {
    let mut map = std::collections::BTreeMap::new();
    for &i in indices {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        let xi = Scalar::from(i as u64);
        for &j in indices {
            if i == j { continue; }
            let xj = Scalar::from(j as u64);
            num *= -xj;                // ✅ FIXED: multiply by -x_j (since we want (0-x_j))
            den *= xi - xj;            // ✅ CORRECT: (x_i - x_j)
        }
        let li = num * den.invert();
        map.insert(i, li);
        
        // Debug output to verify
        // println!("λ_{} = {:?}", i, li.to_bytes());
    }
    map
}

// Helper: convert DB pubkey that may be hex or bs58 into 32-byte vec
fn pubkey_bytes_from_db(s: &str) -> Result<Vec<u8>, String> {
    // Try hex first
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 32 {
            return Ok(bytes);
        } else {
            return Err(format!("hex pubkey length != 32: {}", bytes.len()));
        }
    }
    // Fallback to bs58
    match bs58::decode(s).into_vec() {
        Ok(bytes) => {
            if bytes.len() == 32 {
                Ok(bytes)
            } else {
                Err(format!("bs58 pubkey length != 32: {}", bytes.len()))
            }
        }
        Err(e) => Err(format!("invalid pubkey string (neither hex nor bs58): {:?}", e)),
    }
}




async fn do_sign_tx(wallet_id: Uuid, req: SignRequest, store: &Arc<Mutex<Store>>) -> SignResponse {
    // 1) decode message bytes (we expect base64 of Message bytes)
    // If clients provide a base64'ed *unsigned Transaction* you should extract .message()
    // Here we expect req.message contains base64(Message::serialize()).
    let msg_bytes = general_purpose::STANDARD.decode(&req.message).expect("invalid base64 message");
    let msg_slice = msg_bytes.as_slice();

    // 2) load wallet (drop lock quickly)
    let wallet = {
        let mut s = store.lock().unwrap();
        s.get_wallet(wallet_id).expect("wallet not found")
    };

    let X_bytes = pubkey_bytes_from_db(&wallet.pubkey).expect("invalid pubkey in DB");

    // 3) sign session in db
    let session_id = Uuid::new_v4();
    {
        let mut s = store.lock().unwrap();
        let session = SignSession {
            id: session_id,
            wallet_id: Some(wallet_id),
            message_hash: hex::encode(sha2::Sha256::digest(msg_slice)),
            nodes_used: serde_json::json!(node_endpoints()),
            partials: None,
            signature: None,
            status: "commit_phase".into(),
            created_at: None,
        };
        s.insert_sign_session(session).expect("insert sign_session failed");
    }

    // 4) Round A: request nonces (R_i) from nodes
    let client = Client::new();
    let mut Rs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut indices: Vec<u64> = Vec::new();

    for (i, node) in node_endpoints().iter().enumerate() {
        let url = format!("{}/sign/commit", node);
        let body = serde_json::json!({
            "sign_session": session_id.to_string(),
            "wallet_id": wallet_id.to_string(),
            "message_hash": hex::encode(sha2::Sha256::digest(msg_slice)),
            "index": (i as u64) + 1
        });
        let resp: serde_json::Value = client.post(&url)
            .json(&body)
            .send().await.unwrap()
            .json().await.unwrap();

        let R_hex = resp["R"].as_str().unwrap();
        let R_bytes = hex::decode(R_hex).expect("bad R hex");
        Rs.push(((i + 1) as u64, R_bytes));
        indices.push((i + 1) as u64);
    }

    // 5) aggregate R (points)
    let mut R_point = EdwardsPoint::identity();
    for (_idx, r_bytes) in &Rs {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&r_bytes[..32]);
        let comp = CompressedEdwardsY(arr);
        let pt = comp.decompress().expect("invalid R_i point");
        R_point = R_point + pt;
    }
    let R_comp = R_point.compress();
    let R_bytes = R_comp.to_bytes();

    // 6) challenge c = H(R || X || m)
    let c = challenge_scalar(&R_bytes, &X_bytes, msg_slice);
    // DEBUG: Print the values
    // println!("=== CHALLENGE COMPUTATION DEBUG ===");
    // println!("R_bytes (32 bytes): {}", hex::encode(&R_bytes));
    // println!("X_bytes (32 bytes): {}", hex::encode(&X_bytes));  
    // println!("msg_slice ({} bytes): {}", msg_slice.len(), hex::encode(msg_slice));

    // let mut manual_hasher = Sha512::new();
    // manual_hasher.update(&R_bytes);
    // manual_hasher.update(&X_bytes);
    // manual_hasher.update(msg_slice);
    // let manual_hash = manual_hasher.finalize();
    // println!("Manual SHA-512 hash: {}", hex::encode(&manual_hash));

    // let manual_scalar = Scalar::from_bytes_mod_order_wide(&manual_hash.as_slice().try_into().unwrap());
    // println!("Manual challenge scalar: {:?}", manual_scalar.to_bytes());
    // println!("Original challenge scalar: {:?}", c.to_bytes());
    // println!("Challenges match: {}", manual_scalar == c);

    // Also check if we should be using a different domain separator or encoding
    // println!("=== EdDSA STANDARD CHECK ===");


    // 7) Lagrange coefficients
    let lambda_map = lagrange_coeffs_at_zero(&indices);
    

    // 8) ask nodes to respond with z_i
    let mut partials: Vec<(u64, Scalar)> = Vec::new();
    for (i, node) in node_endpoints().iter().enumerate() {
        let idx = (i + 1) as u64;
        let lambda = lambda_map.get(&idx).expect("lambda missing");
        let url = format!("{}/sign/respond", node);
        let body = serde_json::json!({
            "sign_session": session_id.to_string(),
            "wallet_id": wallet_id.to_string(),
            "message_hash": hex::encode(sha2::Sha256::digest(msg_slice)),
            "index": idx,
            "challenge": hex::encode(c.to_bytes()),
            "lambda": hex::encode(lambda.to_bytes()),
        });

        let resp: serde_json::Value = client.post(&url)
            .json(&body)
            .send().await.unwrap()
            .json().await.unwrap();

        let z_hex = resp["z"].as_str().unwrap();
        let z_bytes: [u8; 32] = hex::decode(z_hex).unwrap().try_into().unwrap();
        let z_scalar = Scalar::from_canonical_bytes(z_bytes)
            .unwrap_or_else(|| Scalar::from_bytes_mod_order(z_bytes));
        partials.push((idx, z_scalar));
    }

    // 9) aggregate z
    let mut z = Scalar::ZERO;
    for (_i, zi) in &partials {
        z += zi;
    }

    // 10) verify z*G == R + c*X
    let mut x_arr = [0u8; 32];
    x_arr.copy_from_slice(&X_bytes[..32]);
    let X_pt = CompressedEdwardsY(x_arr).decompress().expect("invalid X point");

    let lhs = &ED25519_BASEPOINT_POINT * &z;
    let rhs = R_point + (X_pt * c);

    // DEBUG: Print the values
    // println!("=== SIGNATURE VERIFICATION DEBUG ===");
    // println!("R_point: {:?}", R_point.compress().to_bytes());
    // println!("X_pt: {:?}", X_pt.compress().to_bytes());
    // println!("z: {:?}", z.to_bytes());
    // println!("c: {:?}", c.to_bytes());
    // println!("lhs (z*G): {:?}", lhs.compress().to_bytes());
    // println!("rhs (R + c*X): {:?}", rhs.compress().to_bytes());
    // println!("LHS == RHS: {}", lhs == rhs);

    // // Also debug the individual node responses
    // println!("=== NODE RESPONSES DEBUG ===");
    // for (i, (idx, zi)) in partials.iter().enumerate() {
    //     println!("Node {}: z_{} = {:?}", i+1, idx, zi.to_bytes());
    // }

    if lhs != rhs {
        panic!("signature verification failed (lhs != rhs)");
    }

    // 11) persist signature (store z bytes as hex in DB)
    {
        let mut s = store.lock().unwrap();
        s.update_sign_session_signature(session_id, hex::encode(z.to_bytes())).expect("update sign_session failed");
    }

    // 12) return signature as R||z hex (64 bytes)
    let mut sig_bytes = Vec::new();
    sig_bytes.extend_from_slice(&R_bytes);
    sig_bytes.extend_from_slice(&z.to_bytes());
    let sig_hex = hex::encode(&sig_bytes);

    SignResponse { signature: sig_hex }
}

#[handler]
pub async fn sign_tx(
    Path(wallet_id): Path<Uuid>,
    Json(req): Json<SignRequest>,
    Data(store): Data<&Arc<Mutex<Store>>>
) -> Json<SignResponse> {
    let resp = do_sign_tx(wallet_id, req, store).await;
    Json(resp)
}


/// Request to send SOL or token
#[derive(Deserialize)]
pub struct SendRequest {
    pub to: String,
    pub amount: u64,
    pub token: Option<String>, // default SOL
    pub mint: Option<String>, // required if token is Some
}

#[derive(Serialize)]
pub struct SendResponse {
    // pub tx_base64: String,
    pub signature: String,
}


#[handler]
pub async fn send_tx(
    Path(wallet_id): Path<Uuid>,
    Json(req): Json<SendRequest>,
    Data(store): Data<&Arc<Mutex<Store>>>
) -> Json<SendResponse> {
    // 1) Get wallet
    let wallet = {
        let mut s = store.lock().unwrap();
        s.get_wallet(wallet_id).expect("wallet not found")
    };

    let decoded = pubkey_bytes_from_db(&wallet.pubkey).expect("invalid pubkey in DB");
    let from_pubkey = Pubkey::new_from_array(decoded.try_into().expect("pubkey length must be 32"));
    let to_pubkey = Pubkey::from_str(&req.to).expect("invalid recipient pubkey");

    // 2) RPC client
    let rpc = RpcClient::new("https://api.devnet.solana.com".to_string());
    let recent_blockhash = rpc.get_latest_blockhash().expect("failed to fetch recent blockhash");

    // 3) Build message with appropriate instructions
    let message = if let Some(mint_str) = req.mint.clone() {
        // Token transfer
        let mint_account = Pubkey::from_str(&mint_str).expect("invalid mint pubkey");

        let create_recipient_ata_ix = create_associated_token_account_idempotent(
            &from_pubkey,       // payer
            &to_pubkey,         // wallet address
            &mint_account,      // mint address
            &TOKEN_PROGRAM_ID,
        );

        let sender_token_account = get_associated_token_address(&from_pubkey, &mint_account);
        let recipient_token_account = get_associated_token_address(&to_pubkey, &mint_account);

        // Fetch decimals from mint
        let supply = rpc.get_token_supply(&mint_account).expect("failed to fetch supply");
        let decimals = supply.decimals;

        let transfer_ix = transfer_checked(
            &TOKEN_PROGRAM_ID,
            &sender_token_account,
            &mint_account,
            &recipient_token_account,
            &from_pubkey,
            &[],
            req.amount,
            decimals,
        ).expect("failed to build transfer_checked instruction");

        Message::new_with_blockhash(
            &[create_recipient_ata_ix, transfer_ix], 
            Some(&from_pubkey), 
            &recent_blockhash
        )
    } else {
        // Native SOL transfer
        let ix = system_instruction::transfer(&from_pubkey, &to_pubkey, req.amount);
        Message::new_with_blockhash(&[ix], Some(&from_pubkey), &recent_blockhash)
    };

    // 4) Serialize for signing
    let msg_bytes = message.serialize();
    let msg_base64 = general_purpose::STANDARD.encode(&msg_bytes);

    let sign_req = SignRequest { message: msg_base64.clone() };
    let sign_resp = do_sign_tx(wallet_id, sign_req, store).await;

    // 5) Build signed tx
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = hex::decode(&sign_resp.signature).expect("bad sig hex");
    let sig_arr: [u8; 64] = sig_bytes.try_into().expect("signature must be 64 bytes");
    let sol_sig = Signature::from(sig_arr);
    tx.signatures = vec![sol_sig];

    // 6) Broadcast
    let tx_sig = rpc.send_and_confirm_transaction(&tx).expect("rpc send failed");
    println!("✅ Broadcasted to devnet. TxSig: {}", tx_sig);

    Json(SendResponse {
        // tx_base64: general_purpose::STANDARD.encode(&bincode::serialize(&tx).unwrap_or_default()),
        signature: tx_sig.to_string(),
    })
}