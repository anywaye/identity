


CREATE TABLE oidc_clients (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,

    client_id       text        NOT NULL,

    name            text        NOT NULL,

    secret_digest   text        NOT NULL,

    redirect_uris   text[]      NOT NULL,

    grant_types     text[]      NOT NULL,
    scopes          text[]      NOT NULL,

    revoked_at      timestamptz,
    revoked_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,
    revoke_reason   text,

    created_at      timestamptz NOT NULL DEFAULT now(),
    created_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,

    CONSTRAINT oidc_clients_client_id_length
        CHECK (char_length(client_id) BETWEEN 32 AND 64),
    CONSTRAINT oidc_clients_name_length
        CHECK (char_length(name) BETWEEN 1 AND 120),
    CONSTRAINT oidc_clients_secret_digest_length
        CHECK (char_length(secret_digest) = 64),
    CONSTRAINT oidc_clients_redirect_uris_present
        CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
    CONSTRAINT oidc_clients_grant_types_present
        CHECK (cardinality(grant_types) >= 1),
    CONSTRAINT oidc_clients_scopes_present
        CHECK (cardinality(scopes) >= 1),
    CONSTRAINT oidc_clients_revocation_is_whole
        CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE UNIQUE INDEX oidc_clients_client_id_key ON oidc_clients (client_id);

CREATE INDEX oidc_clients_account_id_idx ON oidc_clients (account_id);


CREATE TABLE oidc_auth_requests (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    client_row_id       uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,

    redirect_uri        text        NOT NULL,
    state               text        NOT NULL,
    nonce               text        NOT NULL,
    response_type       text        NOT NULL,
    response_mode       text        NOT NULL,
    scopes              text[]      NOT NULL,
    code_challenge      text        NOT NULL,
    code_challenge_method text      NOT NULL,
    login_hint          text        NOT NULL DEFAULT '',

    subject             uuid        REFERENCES users (id) ON DELETE CASCADE,
    auth_time           timestamptz,

    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,

    code_digest         text,
    code_expires_at     timestamptz,
    code_consumed_at    timestamptz,

    CONSTRAINT oidc_auth_requests_code_challenge_method_is_s256
        CHECK (code_challenge_method = 'S256'),
    CONSTRAINT oidc_auth_requests_code_is_whole
        CHECK ((code_digest IS NULL) = (code_expires_at IS NULL)),
    CONSTRAINT oidc_auth_requests_code_digest_length
        CHECK (code_digest IS NULL OR char_length(code_digest) = 64),
    CONSTRAINT oidc_auth_requests_subject_is_whole
        CHECK ((subject IS NULL) = (auth_time IS NULL))
);

CREATE UNIQUE INDEX oidc_auth_requests_code_digest_key
    ON oidc_auth_requests (code_digest)
    WHERE code_digest IS NOT NULL;

CREATE INDEX oidc_auth_requests_expires_at_idx ON oidc_auth_requests (expires_at);


CREATE TABLE oidc_access_tokens (
    id                  uuid        PRIMARY KEY,

    client_row_id       uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,
    subject             uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scopes              text[]      NOT NULL,
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,

    CONSTRAINT oidc_access_tokens_expiry_is_bounded
        CHECK (expires_at <= issued_at + interval '15 minutes')
);

CREATE INDEX oidc_access_tokens_expires_at_idx ON oidc_access_tokens (expires_at);


DROP TABLE oidc_access_tokens;
DROP TABLE oidc_auth_requests;
DROP TABLE oidc_clients;

