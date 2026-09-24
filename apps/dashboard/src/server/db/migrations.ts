import 'server-only'

/**
 * Schema migrations, applied in order at startup (src/server/db/migrate.ts).
 * Kept in code, not files, so every build carries its own schema. Never edit
 * an applied migration; add a new one.
 *
 * Bearer secrets (session tokens, invitation tokens, recovery codes) are
 * stored only as SHA-256 hashes: they are random and high-entropy, so a
 * plain hash is enough and allows lookups.
 */
export const migrations: readonly { version: string; sql: string }[] = [
  {
    version: '0001_init',
    sql: `
CREATE TABLE users (
    user_id          uuid        PRIMARY KEY,
    display_name     text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
    -- The WebAuthn user handle: random, never the user id (it is stored on authenticators).
    webauthn_user_id bytea       NOT NULL UNIQUE CHECK (octet_length(webauthn_user_id) = 32),
    create_time      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE passkeys (
    credential_id text        PRIMARY KEY, -- base64url
    user_id       uuid        NOT NULL REFERENCES users ON DELETE CASCADE,
    public_key    bytea       NOT NULL,
    counter       bigint      NOT NULL CHECK (counter >= 0),
    transports    text[]      NOT NULL DEFAULT '{}',
    device_type   text        NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
    backed_up     boolean     NOT NULL,
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    create_time   timestamptz NOT NULL DEFAULT now(),
    last_use_time timestamptz
);
CREATE INDEX passkeys_user ON passkeys (user_id);

-- Unused recovery codes; a code is deleted when used.
CREATE TABLE recovery_codes (
    code_hash   bytea       PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users ON DELETE CASCADE,
    create_time timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

CREATE TABLE sessions (
    token_hash     bytea       PRIMARY KEY,
    session_id     uuid        NOT NULL UNIQUE,
    user_id        uuid        NOT NULL REFERENCES users ON DELETE CASCADE,
    -- Signed in with a recovery code: must add a passkey before anything else.
    recovered      boolean     NOT NULL DEFAULT false,
    user_agent     text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    create_time    timestamptz NOT NULL DEFAULT now(),
    last_seen_time timestamptz NOT NULL DEFAULT now(),
    expire_time    timestamptz NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expire_time);

-- WebAuthn challenges: single use, minutes long, bound to the browser that
-- asked (the id is in an HttpOnly cookie).
CREATE TABLE webauthn_challenges (
    challenge_id uuid        PRIMARY KEY,
    challenge    text        NOT NULL,
    purpose      text        NOT NULL CHECK (purpose IN ('sign_up', 'sign_in', 'add_passkey')),
    user_id      uuid        REFERENCES users ON DELETE CASCADE,
    pending      jsonb,
    expire_time  timestamptz NOT NULL
);
CREATE INDEX webauthn_challenges_expiry ON webauthn_challenges (expire_time);

-- A workspace is a tenant of the services: its id is their tenant_id.
CREATE TABLE workspaces (
    workspace_id uuid        PRIMARY KEY,
    name         text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    create_time  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    workspace_id uuid        NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users ON DELETE CASCADE,
    role         text        NOT NULL CHECK (role IN ('owner', 'member')),
    create_time  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX memberships_user ON memberships (user_id);

CREATE TABLE invitations (
    token_hash    bytea       PRIMARY KEY,
    invitation_id uuid        NOT NULL UNIQUE,
    workspace_id  uuid        NOT NULL REFERENCES workspaces ON DELETE CASCADE,
    role          text        NOT NULL CHECK (role IN ('owner', 'member')),
    created_by    uuid        REFERENCES users ON DELETE SET NULL,
    create_time   timestamptz NOT NULL DEFAULT now(),
    expire_time   timestamptz NOT NULL,
    accepted_by   uuid        REFERENCES users ON DELETE SET NULL,
    accept_time   timestamptz,
    revoke_time   timestamptz
);
CREATE INDEX invitations_workspace ON invitations (workspace_id);
`,
  },
]
