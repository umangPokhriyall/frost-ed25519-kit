// @generated automatically by Diesel CLI.

diesel::table! {
    audit_log (id) {
        id -> Uuid,
        event_type -> Text,
        wallet_id -> Nullable<Uuid>,
        payload -> Jsonb,
        timestamp -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    dkg_sessions (id) {
        id -> Uuid,
        wallet_id -> Nullable<Uuid>,
        round -> Int4,
        messages -> Jsonb,
        state -> Text,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    sign_sessions (id) {
        id -> Uuid,
        wallet_id -> Nullable<Uuid>,
        message_hash -> Text,
        nodes_used -> Jsonb,
        partials -> Nullable<Jsonb>,
        signature -> Nullable<Text>,
        status -> Text,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    wallets (id) {
        id -> Uuid,
        pubkey -> Text,
        threshold -> Int4,
        participants -> Int4,
        nodes -> Jsonb,
        status -> Text,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(dkg_sessions -> wallets (wallet_id));
diesel::joinable!(sign_sessions -> wallets (wallet_id));

diesel::allow_tables_to_appear_in_same_query!(
    audit_log,
    dkg_sessions,
    sign_sessions,
    wallets,
);
