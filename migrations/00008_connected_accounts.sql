
-- +goose Up

CREATE TYPE oauth_provider AS ENUM ('google', 'github');

CREATE TABLE connected_accounts (
    id                       uuid            PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                  uuid            NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider                 oauth_provider  NOT NULL,
    provider_uid             text            NOT NULL,

    access_token_ciphertext  text            NOT NULL,
    refresh_token_ciphertext text,
    expires_at               timestamptz,

    created_at               timestamptz    NOT NULL DEFAULT now(),
    updated_at               timestamptz    NOT NULL DEFAULT now(),

    CONSTRAINT connected_accounts_provider_uid_length
        CHECK (char_length(provider_uid) BETWEEN 1 AND 255),

    CONSTRAINT connected_accounts_access_token_ciphertext_length
        CHECK (char_length(access_token_ciphertext) BETWEEN 4 AND 4096)
);

CREATE UNIQUE INDEX connected_accounts_provider_uid_key
    ON connected_accounts (provider, provider_uid);

CREATE INDEX connected_accounts_user_id_idx ON connected_accounts (user_id);

-- +goose Down

DROP TABLE connected_accounts;
DROP TYPE oauth_provider;