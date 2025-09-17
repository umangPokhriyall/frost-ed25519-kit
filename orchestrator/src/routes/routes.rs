use poem:: { handler, web:: Path, web:: Json };
use serde:: { Deserialize, Serialize };
use uuid:: Uuid;
use reqwest:: Client;
use k256::{ProjectivePoint, AffinePoint, EncodedPoint};
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use anyhow::Result;

#[derive(Deserialize)]
pub struct CreateWalletRequest {
    pub threshold: usize,
    pub participants: usize,
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub wallet_id: Uuid,
    pub aggregate_pubkey: String,
}


#[derive(Deserialize, Serialize, Clone)]
pub struct Round1Response {
    pub commitments: Vec<String>,         // hex-encoded points (C0..Ct-1)
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
pub async fn create_wallet(Json(req): Json<CreateWalletRequest>) -> Json<CreateWalletResponse> {
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
            final_shares.push((i, share_hex));
        } else {
            panic!("No final share from node {}", node);
        }

    }

    // --- Compute aggregate public key from constant-term commitments (C0 of each dealer)
    // X = sum_i C_{i,0}
    let mut agg_point = ProjectivePoint::IDENTITY;

    for r1 in &round1_responses {
        // parse first commitment (C0)
        let c0_hex = &r1.commitments[0];
        let bytes = hex::decode(c0_hex).expect("invalid c0 hex");
        let ep = EncodedPoint::from_bytes(&bytes).expect("invalid encoded point bytes");
        let affine = AffinePoint::from_encoded_point(&ep).expect("invalid affine");
        let pt = ProjectivePoint::from(affine);
        agg_point += pt;
    }

    let agg_pubkey_hex = hex::encode(AffinePoint::from(agg_point).to_encoded_point(false).as_bytes());

    Json(CreateWalletResponse {
        wallet_id,
        aggregate_pubkey: agg_pubkey_hex,
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

#[handler]
pub async fn sign_tx(Path(wallet_id): Path<Uuid>, Json(req): Json<SignRequest>) -> Json < SignResponse > {
    // TODO: Start signing session over Redis, aggregate partials

    println!("Sign request for wallet {}: {}", wallet_id, req.message);

    // Placeholder signature
    let signature = "FakeSignatureABC".to_string();

    Json(SignResponse { signature })
}
