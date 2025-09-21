use diesel::prelude::*;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::schema::{wallets, dkg_sessions, sign_sessions, audit_log};
use chrono::NaiveDateTime;

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = wallets)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Wallet {
    pub id: Uuid,
    pub pubkey: String,
    pub threshold: i32,
    pub participants: i32,
    pub nodes: serde_json::Value,
    pub status: String,
}

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = dkg_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DkgSession {
    pub id: Uuid,
    pub wallet_id: Option<Uuid>,
    pub round: i32,
    pub messages: serde_json::Value,
    pub state: String,
}

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = sign_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct SignSession {
    pub id: Uuid,
    pub wallet_id: Option<Uuid>,
    pub message_hash: String,
    pub nodes_used: serde_json::Value,
    pub partials: Option<serde_json::Value>,
    pub signature: Option<String>,
    pub status: String,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = audit_log)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuditLog {
    pub id: Uuid,
    pub event_type: String,
    pub wallet_id: Option<Uuid>,
    pub payload: serde_json::Value,
}
