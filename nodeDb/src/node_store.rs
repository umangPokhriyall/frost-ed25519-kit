use crate::config::Config;
use diesel::prelude::*;
use diesel::Connection;
use std::collections::HashMap;
use uuid::Uuid;
use curve25519_dalek::scalar::Scalar;

pub struct NodeStore {
    pub conn: PgConnection,
    pub nonces: HashMap<Uuid, Scalar>,
}

impl NodeStore {
    pub fn new() -> Result<Self, ConnectionError> {
        let config: Config = Config::default();
        let conn: PgConnection = PgConnection::establish(&config.db_url)?;
        Ok(Self { conn, nonces: HashMap::new() })
    }

    pub fn store_nonce(&mut self, sid: Uuid, r: Scalar) {
        self.nonces.insert(sid, r);
    }
    pub fn take_nonce(&mut self, sid: &Uuid) -> Option<Scalar> {
        self.nonces.remove(sid)
    }
}