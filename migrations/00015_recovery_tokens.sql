
-- +goose Up

CREATE TABLE recovery_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    purpose         text        NOT NULL,

    token_digest    text        NOT NULL,

    target_email    text,

    target_token_digest text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    token_consumed_at  timestamptz,
    target_consumed_at timestamptz,

    CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email')),

    CONSTRAINT recovery_tokens_digest_length
        CHECK (char_length(token_digest) = 64),

    CONSTRAINT recovery_tokens_expiry_is_after_creation
        CHECK (expires_at > created_at),

    CONSTRAINT recovery_tokens_target_is_for_an_email_change
        CHECK ((purpose = 'email_change') = (target_email IS NOT NULL)),

    CONSTRAINT recovery_tokens_target_needs_a_confirmed_first_side
        CHECK (target_token_digest IS NULL OR token_consumed_at IS NOT NULL),

    CONSTRAINT recovery_tokens_target_confirmation_needs_the_first
        CHECK (target_consumed_at IS NULL OR token_consumed_at IS NOT NULL),

    CONSTRAINT recovery_tokens_target_digest_length
        CHECK (target_token_digest IS NULL OR char_length(target_token_digest) = 64),

    CONSTRAINT recovery_tokens_target_email_is_normalized
        CHECK (target_email IS NULL OR target_email = lower(target_email))
);

CREATE UNIQUE INDEX recovery_tokens_token_digest_key
    ON recovery_tokens (token_digest);

CREATE UNIQUE INDEX recovery_tokens_target_digest_key
    ON recovery_tokens (target_token_digest)
    WHERE target_token_digest IS NOT NULL;

CREATE INDEX recovery_tokens_user_purpose_idx
    ON recovery_tokens (user_id, purpose, created_at DESC);

CREATE INDEX recovery_tokens_expires_at_idx
    ON recovery_tokens (expires_at);

-- +goose Down

DROP TABLE recovery_tokens;