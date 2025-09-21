use diesel::prelude::*;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::schema::{shares, node_identity};

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = shares)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Share {
    pub id: Uuid,
    pub wallet_id: Uuid,
    pub final_share_enc: String,
    pub pub_share: String,
}

#[derive(Queryable, Selectable, Insertable, Serialize, Deserialize)]
#[diesel(table_name = node_identity)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NodeIdentity {
    pub id: Uuid,
    pub node_pubkey: String,
    pub node_privkey_enc: String,
}
