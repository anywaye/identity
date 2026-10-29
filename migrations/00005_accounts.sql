
-- +goose Up

CREATE TYPE account_role AS ENUM ('owner', 'admin', 'member');

CREATE TABLE accounts (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    slug        text        NOT NULL,
    personal    boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT accounts_name_length CHECK (char_length(name) BETWEEN 1 AND 120),

    CONSTRAINT accounts_slug_format CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),

    CONSTRAINT accounts_slug_length CHECK (char_length(slug) BETWEEN 1 AND 63)
);

CREATE UNIQUE INDEX accounts_slug_key ON accounts (slug);

-- +goose Down

DROP INDEX accounts_slug_key;
DROP TABLE accounts;
DROP TYPE account_role;
