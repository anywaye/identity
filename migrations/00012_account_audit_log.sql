

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

CREATE FUNCTION account_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'account_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER account_audit_log_append_only
    BEFORE UPDATE OR DELETE ON account_audit_log
    FOR EACH ROW EXECUTE FUNCTION account_audit_log_is_append_only();


DROP TRIGGER account_audit_log_append_only ON account_audit_log;
DROP FUNCTION account_audit_log_is_append_only();
DROP TABLE account_audit_log;
