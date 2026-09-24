-- The audit trail: one hash chain per tenant (see internal/chain).

-- The head of each tenant's chain. Appending locks it (FOR UPDATE), which
-- serializes appends per tenant and keeps sequence numbers gapless.
CREATE TABLE chains (
    tenant_id     uuid   PRIMARY KEY,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    last_hash     bytea  NOT NULL
);

CREATE TABLE events (
    tenant_id    uuid        NOT NULL,
    sequence     bigint      NOT NULL CHECK (sequence >= 1),
    event_id     uuid        NOT NULL,
    occur_time   timestamptz NOT NULL,
    record_time  timestamptz NOT NULL,
    actor_kind   text        NOT NULL,
    actor_id     text        NOT NULL,
    on_behalf_of text        NOT NULL,
    action       text        NOT NULL,
    target_type  text        NOT NULL,
    target_id    text        NOT NULL,
    outcome      text        NOT NULL,
    reason       text        NOT NULL,
    request_id   text        NOT NULL,
    details      jsonb       NOT NULL,
    source       text        NOT NULL,
    prev_hash    bytea       NOT NULL,
    hash         bytea       NOT NULL,
    PRIMARY KEY (tenant_id, sequence),
    UNIQUE (tenant_id, event_id)
);
CREATE INDEX events_newest ON events (tenant_id, occur_time DESC, sequence DESC);
CREATE INDEX events_by_actor ON events (tenant_id, actor_id, occur_time DESC);
CREATE INDEX events_for_user ON events (tenant_id, on_behalf_of, occur_time DESC);

-- Append-only: the service never changes or removes events. (The hash chain
-- still reveals a change made by someone who disables this.)
CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END $$;
CREATE TRIGGER events_no_update_or_delete BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER events_no_truncate BEFORE TRUNCATE ON events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
