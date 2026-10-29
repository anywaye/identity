
-- +goose Up

CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_digest text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    user_agent   text,
    ip           inet,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);


CREATE UNIQUE INDEX sessions_token_digest_key ON sessions (token_digest);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- +goose Down

DROP TABLE sessions;
