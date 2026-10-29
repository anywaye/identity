
-- +goose Up

CREATE TABLE account_audit_log (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    account_id   uuid        NOT NULL,

    action       text        NOT NULL,

    actor_user_id uuid       NOT NULL,
    actor_key_id  uuid       NOT NULL,

    target      text        NOT NULL,
    affected    integer     NOT NULL,

    trace_id    text        NOT NULL,

    occurred_at timestamptz NOT NULL,

    CONSTRAINT account_audit_log_affected_not_negative CHECK (affected >= 0),
    CONSTRAINT account_audit_log_target_length
        CHECK (char_length(target) BETWEEN 1 AND 64),
    CONSTRAINT account_audit_log_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);

CREATE INDEX account_audit_log_account_idx
	ON account_audit_log (account_id, occurred_at DESC, id DESC);

-- THE APPEND-ONLY TRIGGER, which is the actual security property.
--
-- It lives in the DATABASE and not in the service, and that placement is the
-- whole argument. A service that refuses to UPDATE its own audit rows is a
-- service with a bug-shaped hole in it: the next packet adds an endpoint, or an
-- operator runs a repair script, or somebody connects with psql and fixes a row
-- "just to check", and the trail is editable by the admin whose action is in it.
-- The packet's requirement is that the record cannot be edited BY THE ADMIN WHO
-- PERFORMED IT, and a constraint in Go cannot say that about a psql session.
--
-- It fires on UPDATE and DELETE, never on INSERT, and never on TRUNCATE — a
-- TRUNCATE does not fire row-level triggers, which is how dbtest.Reset can still
-- wipe the table between deliberate runs.
--
-- The StatementBegin/End pair is not decoration: goose splits a migration on
-- semicolons, and a plpgsql body is full of them. Without the markers the body
-- is cut in half and the migration fails with "unterminated dollar-quoted
-- string", which reads like a quoting mistake rather than a missing marker.
-- +goose StatementBegin
CREATE FUNCTION account_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'account_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER account_audit_log_append_only
    BEFORE UPDATE OR DELETE ON account_audit_log
    FOR EACH ROW EXECUTE FUNCTION account_audit_log_is_append_only();

-- +goose Down

DROP TRIGGER account_audit_log_append_only ON account_audit_log;
DROP FUNCTION account_audit_log_is_append_only();
DROP TABLE account_audit_log;
