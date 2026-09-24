-- Things to tell users on their phones (push notifications): an outbox the
-- app API claims, sends through APNs and completes. Rows carry no task
-- content, only what happened.
CREATE TABLE notifications (
    id            bigserial   PRIMARY KEY,
    tenant_id     uuid        NOT NULL,
    user_id       text        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('approval_needed', 'confirmation_needed', 'task_finished')),
    task_id       uuid        NOT NULL,
    task_state    text        NOT NULL,
    claimed_by    text,
    claimed_until timestamptz,
    attempts      integer     NOT NULL DEFAULT 0,
    done_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_pending ON notifications (id) WHERE done_at IS NULL;
