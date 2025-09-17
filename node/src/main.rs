// node_agent.rs
// Cargo.toml must include: poem, k256, rand_core/rand, serde, serde_json, tokio, hex, anyhow, tracing
use poem::{handler, post, web::Json, Route, Server};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

use k256::{ProjectivePoint, AffinePoint, EncodedPoint, Scalar};
use k256::elliptic_curve::Field; // for Scalar::random
use k256::elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint};
use k256::elliptic_curve::ff::PrimeField; // for Scalar::from_repr

use anyhow::{Result, anyhow};

#[derive(Deserialize)]
struct Round1Request {
    wallet_id: String,
    threshold: usize,
    participants: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Round1Response {
    pub commitments: Vec<String>,         // hex-encoded encoded points (C0, C1, ...)
    pub shares: Vec<(u64, String)>,      // (recipient_index, hex-encoded scalar)
}

// Helper: sample polynomial coefficients (degree = threshold - 1)
fn sample_poly(threshold: usize) -> Vec<Scalar> {
    (0..threshold)
        .map(|_| Scalar::random(&mut OsRng))
        .collect()
}

// Helper: evaluate polynomial at x (x as u64)
fn eval_poly(coeffs: &[Scalar], x: u64) -> Scalar {
    let mut res = Scalar::ZERO;
    let mut pow = Scalar::ONE;
    let x_scalar = Scalar::from(x);
    for c in coeffs.iter() {
        res += *c * pow;
        pow *= x_scalar;
    }
    res
}

// encode ProjectivePoint to hex
fn encode_point_hex(p: &ProjectivePoint) -> String {
    // convert to affine for encoding
    let affine = AffinePoint::from(*p);
    // encode uncompressed (SEC1) bytes
    let ep = affine.to_encoded_point(false);
    hex::encode(ep.as_bytes())
}

// decode hex to ProjectivePoint
fn decode_point_hex(hex_str: &str) -> Result<ProjectivePoint> {
    let bytes = hex::decode(hex_str)?;
    let ep = EncodedPoint::from_bytes(&bytes)
        .map_err(|e| anyhow!("encoded point parse error: {:?}", e))?;
    let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let affine = affine.ok_or_else(|| anyhow!("invalid encoded point"))?;
    Ok(ProjectivePoint::from(affine))
}



// encode scalar to hex
fn encode_scalar_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

// decode scalar from hex
fn decode_scalar_hex(hex_str: &str) -> Result<Scalar> {
    let b = hex::decode(hex_str)?;
    let fb: [u8; 32] = b.try_into().map_err(|_| anyhow!("invalid scalar length"))?;
    Ok(Scalar::from_repr(fb.into()).unwrap()) // will reduce automatically
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
            let pt = ProjectivePoint::GENERATOR * c;
            encode_point_hex(&pt)
        })
        .collect();

    // compute shares for recipient indices 1..participants
    let mut shares = Vec::new();
    for i in 1..=(req.participants as u64) {
        let s = eval_poly(&coeffs, i);
        shares.push((i, encode_scalar_hex(&s)));
    }

    let response = Round1Response { commitments, shares };
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
async fn round2(Json(req): Json<Round2Request>) -> Json<Round2Response> {
    // For each dealer (round1 entry), verify the share they sent to me
    // If any verification fails, return ack = false and the dealer index (0-based)
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
        let lhs = ProjectivePoint::GENERATOR * share;

        // RHS = sum_{k=0}^{t-1} C_{k} * (my_index^k)
        let mut rhs = ProjectivePoint::IDENTITY;
        let x = req.my_index;
        let mut pow = Scalar::ONE;
        let x_scalar = Scalar::from(x);
        for c_hex in r1.commitments.iter() {
            // decode C_k point
            match decode_point_hex(c_hex) {
                Ok(point) => {
                    // multiply point by pow
                    let term = point * pow;
                    rhs += term;
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

    Json(Round2Response {
        ack: true,
        failing_dealer: None,
        my_final_share: Some(encode_scalar_hex(&total)),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    let app = Route::new()
        .at("/dkg/round1/start", post(round1))
        .at("/dkg/round2/verify", post(round2));

    println!("NodeAgent running on 127.0.0.1:4002");
    Server::new(poem::listener::TcpListener::bind("127.0.0.1:4002"))
        .run(app)
        .await?;

    Ok(())
}
