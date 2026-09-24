-- Orchestrator state. Provider keys are never stored; device client keys are
-- Vault-sealed blobs. Transcripts are kept only for ORCH_TRANSCRIPT_RETENTION.

-- A voice session. `tools` maps each tool name offered to the realtime model
-- to what it runs; `user_turn` is the highest user turn the gateway reported.
CREATE TABLE conversations (
    id          uuid        PRIMARY KEY,
    tenant_id   uuid        NOT NULL,
    user_id     text        NOT NULL CHECK (char_length(user_id) BETWEEN 1 AND 128),
    session_id  text        NOT NULL DEFAULT '',
    provider    smallint    NOT NULL,
    locale      text        NOT NULL DEFAULT '',
    tools       jsonb       NOT NULL,
    user_turn   bigint      NOT NULL DEFAULT 0,
    closed_at   timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX conversations_owner ON conversations (tenant_id, user_id, created_at DESC);

CREATE TABLE turns (
    conversation_id uuid        NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    role            text        NOT NULL CHECK (role IN ('user', 'assistant')),
    item_id         text        NOT NULL,
    user_turn       bigint      NOT NULL,
    text            text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, role, item_id)
);

-- Results of the realtime model's calls, so a retried call is not run twice.
CREATE TABLE tool_calls (
    conversation_id uuid        NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    call_id         text        NOT NULL,
    name            text        NOT NULL,
    output          text        NOT NULL,
    is_error        boolean     NOT NULL,
    ack_required    boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, call_id)
);

-- Background work: an agent loop ('agent') or a single device command
-- waiting for approval ('command'). `history` is the agent's items and
-- `pending` the tool calls of the current step not yet run (protojson).
CREATE TABLE tasks (
    id              uuid        PRIMARY KEY,
    tenant_id       uuid        NOT NULL,
    user_id         text        NOT NULL,
    conversation_id uuid        REFERENCES conversations (id) ON DELETE SET NULL,
    kind            text        NOT NULL CHECK (kind IN ('agent', 'command')),
    provider        smallint    NOT NULL,
    goal            text        NOT NULL,
    state           text        NOT NULL CHECK (state IN ('queued', 'running', 'awaiting_confirmation',
                                                          'awaiting_approval', 'succeeded', 'failed', 'cancelled')),
    result          text        NOT NULL DEFAULT '',
    steps           integer     NOT NULL DEFAULT 0,
    tools           jsonb       NOT NULL DEFAULT '{}',
    history         jsonb       NOT NULL DEFAULT '[]',
    pending         jsonb       NOT NULL DEFAULT '[]',
    lease_owner     text,
    lease_until     timestamptz,
    deadline        timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tasks_runnable ON tasks (updated_at) WHERE state IN ('queued', 'running');
CREATE INDEX tasks_owner ON tasks (tenant_id, user_id, created_at DESC);

-- Actions waiting for the user's "yes". `asked_turn` is the user turn at
-- which the question reached the user (NULL until then): only a later turn
-- can confirm.
CREATE TABLE confirmations (
    id              uuid        PRIMARY KEY,
    conversation_id uuid        NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    task_id         uuid        REFERENCES tasks (id) ON DELETE CASCADE,
    call_id         text        NOT NULL DEFAULT '',
    action          jsonb       NOT NULL,
    summary         text        NOT NULL,
    asked_turn      bigint,
    state           text        NOT NULL CHECK (state IN ('pending', 'confirmed', 'cancelled', 'expired')),
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX confirmations_conversation ON confirmations (conversation_id) WHERE state = 'pending';

-- Things to tell the user; `event` is a serialized ConversationEvent.
CREATE TABLE events (
    id              bigserial   PRIMARY KEY,
    conversation_id uuid        NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    event           bytea       NOT NULL,
    confirmation_id uuid,
    acked_turn      bigint,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_conversation ON events (conversation_id, id);

CREATE TABLE devices (
    id                uuid        PRIMARY KEY,
    tenant_id         uuid        NOT NULL,
    user_id           text        NOT NULL,
    name              text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    address           text        NOT NULL,
    server_name       text        NOT NULL,
    ca_pem            text        NOT NULL,
    client_cert_pem   text        NOT NULL,
    client_key_sealed bytea       NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, name)
);

-- Device commands waiting for a signed approval (the device's approval id).
CREATE TABLE device_approvals (
    approval_id text        PRIMARY KEY,
    device_id   uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    task_id     uuid        NOT NULL REFERENCES tasks (id) ON DELETE CASCADE,
    call_id     text        NOT NULL,
    command     jsonb       NOT NULL,
    payload     bytea       NOT NULL, -- what the approver signs, as the device sent it
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Turning a closed conversation into long-term memory.
CREATE TABLE memory_jobs (
    conversation_id uuid        PRIMARY KEY REFERENCES conversations (id) ON DELETE CASCADE,
    state           text        NOT NULL CHECK (state IN ('queued', 'running', 'done', 'failed')),
    attempts        integer     NOT NULL DEFAULT 0,
    lease_until     timestamptz,
    not_before      timestamptz NOT NULL DEFAULT now(),
    last_error      text        NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX memory_jobs_runnable ON memory_jobs (not_before) WHERE state IN ('queued', 'running');
