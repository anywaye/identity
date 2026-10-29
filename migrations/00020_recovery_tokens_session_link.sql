

ALTER TABLE recovery_tokens
    DROP CONSTRAINT recovery_tokens_purpose_is_known,
    ADD  CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email', 'session_link'));


ALTER TABLE recovery_tokens
    DROP CONSTRAINT recovery_tokens_purpose_is_known,
    ADD  CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email'));