use diesel::prelude::*;
use uuid::Uuid;
use crate::module::*;
use crate::schema::*;
use crate::store::Store;

impl Store {
    // Create a new wallet record
    pub fn insert_wallet(&mut self, wallet: Wallet) -> Result<Wallet, diesel::result::Error> {
        diesel::insert_into(wallets::table)
            .values(&wallet)
            .returning(Wallet::as_returning())
            .get_result(&mut self.conn)
    }

    pub fn get_wallet(&mut self, wid: Uuid) -> Result<Wallet, diesel::result::Error> {
        use crate::schema::wallets::dsl::*;
        wallets
            .filter(id.eq(wid))
            .select(Wallet::as_select())
            .first(&mut self.conn)
    }

    // DKG sessions
    pub fn insert_dkg_session(&mut self, session: DkgSession) -> Result<DkgSession, diesel::result::Error> {
        diesel::insert_into(dkg_sessions::table)
            .values(&session)
            .returning(DkgSession::as_returning())
            .get_result(&mut self.conn)
    }

    // Sign sessions
    pub fn insert_sign_session(&mut self, session: SignSession) -> Result<SignSession, diesel::result::Error> {
        diesel::insert_into(sign_sessions::table)
            .values(&session)
            .returning(SignSession::as_returning())
            .get_result(&mut self.conn)
    }

    pub fn update_sign_session_signature(
        &mut self,
        sid: Uuid,
        sig: String,
    ) -> Result<usize, diesel::result::Error> {
        use crate::schema::sign_sessions::dsl::*;
        diesel::update(sign_sessions.filter(id.eq(sid)))
            .set((signature.eq(Some(sig)), status.eq("complete")))
            .execute(&mut self.conn)
    }

    // Audit log
    pub fn insert_audit(&mut self, log: AuditLog) -> Result<AuditLog, diesel::result::Error> {
        diesel::insert_into(audit_log::table)
            .values(&log)
            .returning(AuditLog::as_returning())
            .get_result(&mut self.conn)
    }
}
