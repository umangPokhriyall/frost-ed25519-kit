-- Your SQL goes here
CREATE TABLE wallets (
    id UUID PRIMARY KEY,
    pubkey TEXT NOT NULL,
    threshold INTEGER NOT NULL,
    participants INTEGER NOT NULL,
    nodes JSONB NOT NULL, -- list of node ids/urls
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE dkg_sessions (
    id UUID PRIMARY KEY,
    wallet_id UUID REFERENCES wallets(id) ON DELETE CASCADE,
    round INTEGER NOT NULL,
    messages JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE sign_sessions (
    id UUID PRIMARY KEY,
    wallet_id UUID REFERENCES wallets(id) ON DELETE CASCADE,
    message_hash TEXT NOT NULL,
    nodes_used JSONB NOT NULL,
    partials JSONB DEFAULT '[]',
    signature TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    wallet_id UUID,
    payload JSONB NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);