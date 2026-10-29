
-- +goose Up

CREATE TABLE oidc_refresh_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    client_row_id   uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,

    subject         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    token_digest    text        NOT NULL,

    scopes          text[]      NOT NULL,

    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    revoked_at      timestamptz,

    used_at         timestamptz,

    replaced_by     uuid        REFERENCES oidc_refresh_tokens (id) ON DELETE SET NULL,

    CONSTRAINT oidc_refresh_tokens_digest_length
        CHECK (char_length(token_digest) = 64)
);

CREATE UNIQUE INDEX oidc_refresh_tokens_token_digest_key
    ON oidc_refresh_tokens (token_digest);

CREATE INDEX oidc_refresh_tokens_root_key
    ON oidc_refresh_tokens (replaced_by)
    WHERE replaced_by IS NOT NULL;

CREATE INDEX oidc_refresh_tokens_client_key
    ON oidc_refresh_tokens (client_row_id)
    WHERE revoked_at IS NULL;

-- +goose Down

DROP TABLE oidc_refresh_tokens;
