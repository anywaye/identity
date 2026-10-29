
-- +goose Up
ALTER TYPE oauth_provider ADD VALUE 'microsoft';

-- +goose Down

ALTER TYPE oauth_provider RENAME TO oauth_provider_retired;

CREATE TYPE oauth_provider AS ENUM ('google', 'github');

ALTER TABLE connected_accounts
    ALTER COLUMN provider TYPE oauth_provider
    USING provider::text::oauth_provider;

DROP TYPE oauth_provider_retired;
