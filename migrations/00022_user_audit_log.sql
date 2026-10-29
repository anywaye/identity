







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



GRANT SELECT, INSERT ON TABLE user_audit_log TO identity_app;

CREATE FUNCTION user_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'user_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER user_audit_log_append_only
    BEFORE UPDATE OR DELETE ON user_audit_log
    FOR EACH ROW EXECUTE FUNCTION user_audit_log_is_append_only();


DROP TRIGGER user_audit_log_append_only ON user_audit_log;
DROP FUNCTION user_audit_log_is_append_only();
DROP TABLE user_audit_log;