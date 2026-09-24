-- MCP router schema. Credentials are Vault-sealed blobs (SealData); nothing
-- here is usable without the Vault.

CREATE TABLE integrations (
    id                 uuid        PRIMARY KEY,
    tenant_id          uuid        NOT NULL,
    user_id            text        NOT NULL CHECK (char_length(user_id) BETWEEN 1 AND 128),
    display_name       text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    server_url         text        NOT NULL,
    catalog_slug       text,
    auth_kind          text        NOT NULL CHECK (auth_kind IN ('oauth', 'bearer')),
    status             text        NOT NULL CHECK (status IN ('pending', 'connected', 'needs_reauth')),
    status_detail      text        NOT NULL DEFAULT '',
    -- OAuth: the authorization server that issued the tokens, and where to refresh them.
    issuer             text,
    token_endpoint     text,
    redirect_uri       text,
    -- Sealed OAuth tokens (JSON) or bearer token.
    credentials_sealed bytea,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT connected_has_credentials CHECK (status <> 'connected' OR credentials_sealed IS NOT NULL)
);
CREATE INDEX integrations_owner ON integrations (tenant_id, user_id, created_at DESC);

-- OAuth clients the router registered (or was given) per authorization server.
CREATE TABLE oauth_clients (
    issuer               text        NOT NULL,
    redirect_uri         text        NOT NULL,
    client_id            text        NOT NULL,
    client_secret_sealed bytea,
    registration         text        NOT NULL CHECK (registration IN ('dynamic', 'preregistered')),
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, redirect_uri)
);

-- Authorizations waiting for the user. Only a hash of `state` is stored: the
-- state value itself is the capability that completes the flow.
CREATE TABLE pending_authorizations (
    state_hash       bytea       PRIMARY KEY,
    integration_id   uuid        NOT NULL REFERENCES integrations (id) ON DELETE CASCADE,
    issuer           text        NOT NULL,
    token_endpoint   text        NOT NULL,
    resource         text        NOT NULL,
    redirect_uri     text        NOT NULL,
    iss_required     boolean     NOT NULL,
    verifier_sealed  bytea       NOT NULL,
    expires_at       timestamptz NOT NULL
);
CREATE INDEX pending_authorizations_integration ON pending_authorizations (integration_id);
