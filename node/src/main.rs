// node/src/main.rs
use poem::{EndpointExt,handler, post, web::Json, Route, Server};
use rand_core::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use uuid::Uuid;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use nodeDb::node_store::NodeStore;
use nodeDb::node_models::*;
use std::sync::{Arc, Mutex};
use poem::web::Data;
use hex;
use anyhow::{Result, anyhow};
use tracing_subscriber;

#[derive(Deserialize)]
struct Round1Request {
    wallet_id: String,
    threshold: usize,
    participants: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Round1Response {
    pub wallet_id: String,              // <-- add this
    pub commitments: Vec<String>,       // hex-encoded compressed Edwards Y
    pub shares: Vec<(u64, String)>,     // (recipient index, share hex)
}   

// Helper: sample polynomial coefficients (degree = threshold - 1)
fn sample_poly(threshold: usize) -> Vec<Scalar> {
    (0..threshold)
        .map(|_| {
            let mut bytes = [0u8; 64];
            OsRng.fill_bytes(&mut bytes);
            Scalar::from_bytes_mod_order_wide(&bytes)
        })
        .collect()
}

// Helper: evaluate polynomial at x (x as u64)
fn eval_poly(coeffs: &[Scalar], x: u64) -> Scalar {
    let mut pow = Scalar::ONE;
    let mut res = Scalar::ZERO;
    let x_scalar = Scalar::from(x as u64);
    for c in coeffs.iter() {
        res += c * pow;
        pow *= x_scalar;
    }
    res
}

// encode EdwardsPoint to hex (compressed)
fn encode_point_hex(p: &EdwardsPoint) -> String {
    let comp: CompressedEdwardsY = p.compress();
    hex::encode(comp.as_bytes())
}

// decode hex to EdwardsPoint
fn decode_point_hex(hex_str: &str) -> Result<EdwardsPoint> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(anyhow!("invalid point length"));
    }
    let mut arr: [u8; 32] = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let comp = CompressedEdwardsY(arr);
    let pt = comp
        .decompress()
        .ok_or_else(|| anyhow!("invalid compressed Edwards point"))?;
    Ok(pt)
}

// encode scalar to hex (32 bytes)
fn encode_scalar_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

// decode scalar from hex
fn decode_scalar_hex(hex_str: &str) -> Result<Scalar> {
    let b = hex::decode(hex_str)?;
    let fb: [u8; 32] = b.try_into().map_err(|_| anyhow!("invalid scalar length"))?;
    // create Scalar from canonical bytes (reduce if needed)
    Ok(Scalar::from_bytes_mod_order(fb))
}

#[handler]
async fn round1(Json(req): Json<Round1Request>) -> Json<Round1Response> {
    // degree = threshold - 1
    let degree = req.threshold;
    let coeffs = sample_poly(degree);

    // commitments C_k = a_k * G
    let commitments: Vec<String> = coeffs
        .iter()
        .map(|c| {
            let pt = &ED25519_BASEPOINT_POINT * c;
            encode_point_hex(&pt)
        })
        .collect();

    // compute shares for recipient indices 1..participants
    let mut shares = Vec::new();
    for i in 1..=(req.participants as u64) {
        let s = eval_poly(&coeffs, i);
        shares.push((i, encode_scalar_hex(&s)));
    }

    let response = Round1Response {
        wallet_id: req.wallet_id.clone(),   
        commitments,
        shares,
    };
    Json(response)
}

#[derive(Deserialize)]
struct Round2Request {
    all_round1: Vec<Round1Response>, // all dealers' round1 responses
    my_index: u64,
}

#[derive(Serialize)]
struct Round2Response {
    ack: bool,
    failing_dealer: Option<usize>,
    my_final_share: Option<String>, // hex scalar
}

#[handler]
async fn round2(Json(req): Json<Round2Request>, Data(store): Data<&Arc<Mutex<NodeStore>>>) -> Json<Round2Response> {
    // For each dealer (round1 entry), verify the share they sent to me
    for (dealer_idx, r1) in req.all_round1.iter().enumerate() {
        // find the share addressed to my_index
        let maybe = r1.shares.iter().find(|(idx, _)| *idx == req.my_index);
        if maybe.is_none() {
            return Json(Round2Response {
                ack: false,
                failing_dealer: Some(dealer_idx),
                my_final_share: None,
            });
        }
        let (_idx, share_hex) = maybe.unwrap();

        // decode share scalar
        let share = match decode_scalar_hex(share_hex) {
            Ok(s) => s,
            Err(_) => {
                return Json(Round2Response {
                    ack: false,
                    failing_dealer: Some(dealer_idx),
                    my_final_share: None,
                });
            }
        };

        // LHS = share * G
        let lhs = &ED25519_BASEPOINT_POINT * &share;

        // RHS = sum_{k=0}^{t-1} C_{k} * (my_index^k)
        let mut rhs = EdwardsPoint::identity();
        let x = req.my_index;
        let mut pow = Scalar::ONE;
        let x_scalar = Scalar::from(x as u64);
        for c_hex in r1.commitments.iter() {
            // decode C_k point
            match decode_point_hex(c_hex) {
                Ok(point) => {
                    // multiply point by pow
                    let term = point * pow;
                    rhs = rhs + term;
                }
                Err(_) => {
                    return Json(Round2Response {
                        ack: false,
                        failing_dealer: Some(dealer_idx),
                        my_final_share: None,
                    });
                }
            }
            // increment pow *= x
            pow *= x_scalar;
        }

        // compare
        if lhs != rhs {
            // verification failed for this dealer
            return Json(Round2Response {
                ack: false,
                failing_dealer: Some(dealer_idx),
                my_final_share: None,
            });
        }
    }

    // If all checks passed, compute my final share = sum of shares addressed to me
    let mut total = Scalar::ZERO;
    for r1 in req.all_round1.iter() {
        let (_, share_hex) = r1
            .shares
            .iter()
            .find(|(idx, _)| *idx == req.my_index)
            .unwrap();

        let s = match decode_scalar_hex(share_hex) {
            Ok(s) => s,
            Err(_) => {
                return Json(Round2Response {
                    ack: false,
                    failing_dealer: Some(usize::MAX),
                    my_final_share: None,
                });
            }
        };
        total += s;
    }

    let final_share_hex = encode_scalar_hex(&total);

    let mut s = store.lock().unwrap();
    let share_row = Share {
        id: Uuid::new_v4(),
        wallet_id: Uuid::parse_str(&req.all_round1[0].wallet_id).unwrap(), // wallet_id from orchestrator
        final_share_enc: final_share_hex.clone(),
        pub_share: "".to_string(), // you can store pub share if needed
    };
    s.insert_share(share_row).expect("DB insert share failed");

    // IMPORTANT: store `total` locally (encrypted) instead of returning it to orchestrator.
    // For PoC we still return it, but in production you must NOT return the final share.
    Json(Round2Response {
        ack: true,
        failing_dealer: None,
        my_final_share: Some(final_share_hex),
    })
}

// Request types
#[derive(Deserialize)]
struct CommitRequest {
    sign_session: String,
    wallet_id: String,
    message_hash: String,
    index: u64,
}
#[derive(Serialize)]
struct CommitResponse {
    R: String, // hex compressed point
}




#[handler]
async fn sign_commit(Json(req): Json<CommitRequest>, Data(store): Data<&Arc<Mutex<NodeStore>>>) -> Json<CommitResponse> {
    // sample nonce r
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    let r = Scalar::from_bytes_mod_order_wide(&bytes);

    // R = r * G
    let Rpt = &ED25519_BASEPOINT_POINT * &r;
    let Rhex = encode_point_hex(&Rpt);

    // store nonce keyed by sign_session
    {
        let mut s = store.lock().unwrap();
        s.store_nonce(Uuid::parse_str(&req.sign_session).unwrap(), r);
    }

    Json(CommitResponse { R: Rhex })
}


#[derive(Deserialize)]
struct RespondRequest {
    sign_session: String,
    wallet_id: String,
    message_hash: String,
    index: u64,
    challenge: String, // hex
    lambda: String,    // hex
}

#[derive(Serialize)]
struct RespondResponse {
    z: String, // hex scalar
}

#[handler]
async fn sign_respond(Json(req): Json<RespondRequest>, Data(store): Data<&Arc<Mutex<NodeStore>>>) -> Json<RespondResponse> {
    // parse c and lambda
    let c_bytes = hex::decode(&req.challenge).expect("bad challenge hex");
    let c_arr: [u8; 32] = c_bytes.try_into().expect("bad challenge length");
    let c = Scalar::from_canonical_bytes(c_arr).unwrap_or_else(|| Scalar::from_bytes_mod_order(c_arr));

    let lambda_bytes = hex::decode(&req.lambda).expect("bad lambda hex");
    let lambda_arr: [u8; 32] = lambda_bytes.try_into().expect("bad lambda length");
    let lambda = Scalar::from_canonical_bytes(lambda_arr).unwrap_or_else(|| Scalar::from_bytes_mod_order(lambda_arr));

    // load our final share s from DB
    let mut s = store.lock().unwrap();
    let share_row = s.get_share(Uuid::parse_str(&req.wallet_id).unwrap()).expect("share not found");
    let s_arr: [u8; 32] = hex::decode(&share_row.final_share_enc).unwrap().try_into().unwrap();
    let s_scalar = Scalar::from_canonical_bytes(s_arr).unwrap_or_else(|| Scalar::from_bytes_mod_order(s_arr));

    // take nonce r
    let r_opt = s.take_nonce(&Uuid::parse_str(&req.sign_session).unwrap());
    if r_opt.is_none() { panic!("nonce not found"); }
    let r_scalar = r_opt.unwrap();

    // z = r + lambda * s * c
    let z = r_scalar + (c * lambda * s_scalar);

    let z_hex = encode_scalar_hex(&z);
    Json(RespondResponse { z: z_hex })
}





#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let store = Arc::new(Mutex::new(NodeStore::new()?));

    let app = Route::new()
        .at("/dkg/round1/start", post(round1))
        .at("/dkg/round2/verify", post(round2))
        .at("/sign/commit", post(sign_commit))
        .at("/sign/respond", post(sign_respond))
        .data(store);

    println!("NodeAgent running on 127.0.0.1:4001");
    Server::new(poem::listener::TcpListener::bind("127.0.0.1:4001"))
        .run(app)
        .await?;

    Ok(())
}
