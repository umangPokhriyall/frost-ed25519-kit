use diesel::prelude::*;
use uuid::Uuid;
use crate::node_models::*;
use crate::schema::*;
use crate::node_store::NodeStore;

impl NodeStore {
    pub fn insert_share(&mut self, share: Share) -> Result<Share, diesel::result::Error> {
        diesel::insert_into(shares::table)
            .values(&share)
            .returning(Share::as_returning())
            .get_result(&mut self.conn)
    }

    pub fn get_share(&mut self, wid: Uuid) -> Result<Share, diesel::result::Error> {
        use crate::schema::shares::dsl::*;
        shares
            .filter(wallet_id.eq(wid))
            .select(Share::as_select())
            .first(&mut self.conn)
    }

    pub fn insert_node_identity(&mut self, identity: NodeIdentity) -> Result<NodeIdentity, diesel::result::Error> {
        diesel::insert_into(node_identity::table)
            .values(&identity)
            .returning(NodeIdentity::as_returning())
            .get_result(&mut self.conn)
    }

    pub fn get_node_identity(&mut self) -> Result<NodeIdentity, diesel::result::Error> {
        use crate::schema::node_identity::dsl::*;
        node_identity
            .select(NodeIdentity::as_select())
            .first(&mut self.conn)
    }
}
