






-- +goose Up

CREATE TABLE user_audit_log (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id      uuid        NOT NULL,

    action       text        NOT NULL,

    actor_user_id uuid       NOT NULL,
    actor_key_id  uuid       NOT NULL,

    trace_id    text        NOT NULL,

    occurred_at timestamptz NOT NULL,

    CONSTRAINT user_audit_log_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);



-- +goose StatementBegin
GRANT SELECT, INSERT ON TABLE user_audit_log TO identity_app;
-- +goose StatementEnd

-- THE APPEND-ONLY TRIGGER, which is the actual security property.
--
-- The same shape as `account_audit_log_is_append_only` and the same placement, and
-- 00012's argument is not restated: a service that refuses to UPDATE its own audit
-- rows is a service with a bug-shaped hole in it. The next packet adds an endpoint,
-- or an operator runs a repair script, or somebody connects with psql and fixes a
-- row "just to check", and the trail is editable by the operator whose action is in
-- it. A constraint in Go cannot say that about a psql session.
--
-- It fires on UPDATE and DELETE, never on INSERT, and never on TRUNCATE — a TRUNCATE
-- does not fire row-level triggers, which is how dbtest.Reset can still wipe the
-- table between deliberate runs.
--
-- The StatementBegin/End pair is not decoration: goose splits a migration on
-- semicolons, and a plpgsql body is full of them.
-- +goose StatementBegin
CREATE FUNCTION user_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'user_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER user_audit_log_append_only
    BEFORE UPDATE OR DELETE ON user_audit_log
    FOR EACH ROW EXECUTE FUNCTION user_audit_log_is_append_only();

-- +goose Down

DROP TRIGGER user_audit_log_append_only ON user_audit_log;
DROP FUNCTION user_audit_log_is_append_only();
DROP TABLE user_audit_log;