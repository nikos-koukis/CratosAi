-- BYOK Vault schema.
--
-- Secret material is envelope-encrypted by the application (AES-256-GCM, see
-- src/crypto.rs) before it reaches PostgreSQL; the database only ever holds
-- ciphertext. Revocation NULLs every crypto column. PostgreSQL MVCC keeps the
-- previous row version until VACUUM, and WAL and backups keep it longer, so
-- revoked ciphertext stays unreadable only while the KEK is protected.

-- Every KEK that has written to this database. The service refuses to start
-- with a KEK that is not registered here once another one is.
CREATE TABLE kek_registry (
    kek_id      text        PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE provider_keys (
    key_id            uuid        PRIMARY KEY,
    tenant_id         uuid        NOT NULL,
    provider          text        NOT NULL
        CHECK (provider IN ('openai', 'xai', 'anthropic', 'google')),
    label             text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    key_hint          text        NOT NULL CHECK (char_length(key_hint) <= 4),
    status            text        NOT NULL CHECK (status IN ('active', 'revoked')),

    -- Envelope: ciphertext under a per-key DEK; DEK wrapped by the KEK.
    kek_id            text        REFERENCES kek_registry (kek_id),
    wrapped_dek       bytea,
    dek_nonce         bytea,
    ciphertext        bytea,
    nonce             bytea,

    created_by        text        NOT NULL,
    create_time       timestamptz NOT NULL DEFAULT now(),
    revoked_by        text,
    revoke_time       timestamptz,
    revocation_reason text
        CHECK (revocation_reason IN ('user_requested', 'rotated', 'compromised')),

    CONSTRAINT provider_keys_state_consistent CHECK (
        (status = 'active'
            AND kek_id IS NOT NULL AND wrapped_dek IS NOT NULL AND dek_nonce IS NOT NULL
            AND ciphertext IS NOT NULL AND nonce IS NOT NULL
            AND revoked_by IS NULL AND revoke_time IS NULL AND revocation_reason IS NULL)
        OR
        (status = 'revoked'
            AND kek_id IS NULL AND wrapped_dek IS NULL AND dek_nonce IS NULL
            AND ciphertext IS NULL AND nonce IS NULL
            AND revoked_by IS NOT NULL AND revoke_time IS NOT NULL
            AND revocation_reason IS NOT NULL)
    )
);

-- A tenant has at most one ACTIVE key per provider.
CREATE UNIQUE INDEX provider_keys_one_active_per_provider
    ON provider_keys (tenant_id, provider)
    WHERE status = 'active';

CREATE INDEX provider_keys_tenant ON provider_keys (tenant_id);

-- Idempotency records for CreateKey. `payload_fingerprint` is an HMAC keyed
-- from the KEK, never a plain hash of the secret. The key_id reference is
-- deferred because the record is inserted first, to serialise retries.
CREATE TABLE create_key_requests (
    tenant_id           uuid        NOT NULL,
    request_id          uuid        NOT NULL,
    payload_fingerprint bytea       NOT NULL,
    key_id              uuid        NOT NULL
        REFERENCES provider_keys (key_id) DEFERRABLE INITIALLY DEFERRED,
    replaced_key_id     uuid        REFERENCES provider_keys (key_id),
    create_time         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, request_id)
);
