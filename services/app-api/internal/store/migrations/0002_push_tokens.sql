-- Where a session's push notifications go: its phone's APNs device token.
-- A device token belongs to one session at a time (the phone's current one).
CREATE TABLE push_tokens (
    session_id   uuid        PRIMARY KEY REFERENCES sessions (id) ON DELETE CASCADE,
    device_token text        NOT NULL UNIQUE,
    environment  text        NOT NULL CHECK (environment IN ('sandbox', 'production')),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
