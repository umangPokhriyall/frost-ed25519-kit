-- Your SQL goes here
CREATE TABLE shares (
    id UUID PRIMARY KEY,
    wallet_id UUID NOT NULL,
    final_share_enc TEXT NOT NULL, -- encrypted hex
    pub_share TEXT NOT NULL,       -- public verification share
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE node_identity (
    id UUID PRIMARY KEY,
    node_pubkey TEXT NOT NULL,
    node_privkey_enc TEXT NOT NULL, -- encrypted
    created_at TIMESTAMPTZ DEFAULT NOW()
);