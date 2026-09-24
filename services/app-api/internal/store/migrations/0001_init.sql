-- One-time codes that pair an app with a user. Only a SHA-256 of the code is
-- stored.
CREATE TABLE pairing_codes (
    code_hash   bytea       PRIMARY KEY,
    tenant_id   uuid        NOT NULL,
    user_id     text        NOT NULL,
    expires_at  timestamptz NOT NULL,
    redeemed_at timestamptz,
    session_id  uuid,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- A paired app. Its refresh token rotates on every use; only SHA-256 hashes
-- of the current and the previous token are stored. The previous one is
-- accepted for a short grace period (a lost response); after that, using it
-- means the token was copied and ends the session.
CREATE TABLE sessions (
    id                 uuid        PRIMARY KEY,
    tenant_id          uuid        NOT NULL,
    user_id            text        NOT NULL,
    device_name        text        NOT NULL,
    device_model       text        NOT NULL,
    refresh_hash       bytea       NOT NULL UNIQUE,
    previous_hash      bytea       UNIQUE,
    rotated_at         timestamptz,
    refresh_expires_at timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    last_used_at       timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz,
    revoke_reason      text
);
CREATE INDEX sessions_user ON sessions (tenant_id, user_id) WHERE revoked_at IS NULL;
