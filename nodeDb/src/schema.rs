// @generated automatically by Diesel CLI.

diesel::table! {
    node_identity (id) {
        id -> Uuid,
        node_pubkey -> Text,
        node_privkey_enc -> Text,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    shares (id) {
        id -> Uuid,
        wallet_id -> Uuid,
        final_share_enc -> Text,
        pub_share -> Text,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    node_identity,
    shares,
);
