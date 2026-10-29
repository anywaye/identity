

CREATE TABLE api_keys (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,

    name            text        NOT NULL,

    token_digest    text        NOT NULL,

    scopes          text[]      NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),

    expires_at      timestamptz NOT NULL,

    CONSTRAINT api_keys_expires_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT api_keys_maximum_lifetime
        CHECK (expires_at <= created_at + INTERVAL '365 days'),

    last_used_at    timestamptz,

    revoked_at      timestamptz,
    revoked_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,

    revoke_reason   text,

    CONSTRAINT api_keys_token_digest_length
        CHECK (char_length(token_digest) = 64),
    CONSTRAINT api_keys_name_length
        CHECK (char_length(name) BETWEEN 1 AND 80),
    CONSTRAINT api_keys_scopes_not_empty
        CHECK (cardinality(scopes) > 0),
    CONSTRAINT api_keys_revocation_is_whole
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT api_keys_reason_only_when_revoked
        CHECK (revoked_at IS NOT NULL OR revoke_reason IS NULL)
);

CREATE UNIQUE INDEX api_keys_token_digest_key ON api_keys (token_digest);

CREATE INDEX api_keys_account_idx ON api_keys (account_id, created_at DESC, id DESC);

CREATE INDEX api_keys_user_idx ON api_keys (user_id);

CREATE UNIQUE INDEX api_keys_one_live_name_per_account
    ON api_keys (account_id, lower(name))
    WHERE revoked_at IS NULL;

CREATE INDEX api_keys_expires_at_idx ON api_keys (expires_at);


DROP TABLE api_keys;