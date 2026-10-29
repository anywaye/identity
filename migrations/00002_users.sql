
-- +goose Up

CREATE TABLE users (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 text        NOT NULL,
    password_digest       text        NOT NULL,
    failed_login_attempts integer     NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_is_normalized CHECK (email = lower(email)),

    CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 320),

    CONSTRAINT users_failed_login_attempts_non_negative CHECK (failed_login_attempts >= 0)
);

CREATE UNIQUE INDEX users_email_key ON users (email);

-- +goose Down

DROP TABLE users;
