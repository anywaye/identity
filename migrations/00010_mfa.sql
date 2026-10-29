


CREATE TABLE mfa_credentials (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    method              text        NOT NULL,

    secret_ciphertext   text        NOT NULL,

    digits              smallint    NOT NULL,
    period_seconds      integer     NOT NULL,
    algorithm           text        NOT NULL,

    label               text        NOT NULL,

    confirmed_at        timestamptz,

    expires_at          timestamptz,

    failed_attempts     integer     NOT NULL DEFAULT 0,
    locked_until        timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT mfa_credentials_method_is_totp
        CHECK (method = 'totp'),
    CONSTRAINT mfa_credentials_digits
        CHECK (digits IN (6, 8)),
    CONSTRAINT mfa_credentials_period
        CHECK (period_seconds BETWEEN 15 AND 300),
    CONSTRAINT mfa_credentials_algorithm_is_sha1
        CHECK (algorithm = 'SHA1'),
    CONSTRAINT mfa_credentials_secret_present
        CHECK (char_length(secret_ciphertext) BETWEEN 1 AND 512),
    CONSTRAINT mfa_credentials_label_length
        CHECK (char_length(label) BETWEEN 1 AND 200),
    CONSTRAINT mfa_credentials_confirmation_is_whole
        CHECK ((confirmed_at IS NULL) = (expires_at IS NOT NULL)),
    CONSTRAINT mfa_credentials_failed_attempts_not_negative
        CHECK (failed_attempts >= 0)
);

CREATE UNIQUE INDEX mfa_credentials_one_live_per_user
    ON mfa_credentials (user_id, method)
    WHERE confirmed_at IS NOT NULL;

CREATE INDEX mfa_credentials_expires_at_idx
    ON mfa_credentials (expires_at)
    WHERE confirmed_at IS NULL;


CREATE TABLE mfa_recovery_codes (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    credential_id   uuid        NOT NULL REFERENCES mfa_credentials (id) ON DELETE CASCADE,

    code_digest     text        NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),

    used_at         timestamptz,

    CONSTRAINT mfa_recovery_codes_digest_length
        CHECK (char_length(code_digest) = 64)
);

CREATE UNIQUE INDEX mfa_recovery_codes_digest_key
    ON mfa_recovery_codes (credential_id, code_digest);

CREATE INDEX mfa_recovery_codes_unused_idx
    ON mfa_recovery_codes (credential_id)
    WHERE used_at IS NULL;


CREATE TABLE mfa_used_totp_steps (
    credential_id   uuid        NOT NULL REFERENCES mfa_credentials (id) ON DELETE CASCADE,

    step            bigint      NOT NULL,

    used_at         timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (credential_id, step),

    CONSTRAINT mfa_used_totp_steps_step_not_negative
        CHECK (step >= 0)
);


CREATE TABLE mfa_challenges (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    token_digest    text        NOT NULL,

    user_agent      text,
    ip              inet,

    created_at      timestamptz NOT NULL DEFAULT now(),

    expires_at      timestamptz NOT NULL,

    consumed_at     timestamptz,

    CONSTRAINT mfa_challenges_token_digest_length
        CHECK (char_length(token_digest) = 64)
);

CREATE UNIQUE INDEX mfa_challenges_token_digest_key ON mfa_challenges (token_digest);

CREATE INDEX mfa_challenges_expires_at_idx ON mfa_challenges (expires_at);


DROP TABLE mfa_challenges;
DROP TABLE mfa_used_totp_steps;
DROP TABLE mfa_recovery_codes;
DROP TABLE mfa_credentials;
