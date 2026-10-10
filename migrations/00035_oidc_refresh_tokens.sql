-- 00035_oidc_refresh_tokens.sql — the refresh token, and the table that makes
-- rotation and reuse-detection possible.
--
-- WHY THIS TABLE AND NOT A COLELSEWHERE. A refresh token is a long-lived
-- credential, which means it is a NEW SECRET CLASS in a service that already
-- stores three: sessions.token_digest, api_keys.token_digest and
-- oidc_clients.secret_digest. All three are the lower-case hex SHA-256 of a
-- value nobody stores, and this column is the fourth for exactly the reason the
-- other three give: argon2id exists to make GUESSING expensive, 256 bits of
-- crypto/rand has nothing to guess, and the presented value must never reach a
-- place a dump could read. No second scheme, no counting on the value's length,
-- no reversible encoding.
--
-- WHAT IS DELIBERATELY NOT HERE, and it is the interesting part: account_id.
-- This table is not scoped by account, and it is not covered by migration
-- 00016's row-level security, and that is oidc_access_tokens' choice restated
-- rather than a new one. An account-scoped credential table would have to set a
-- session GUC on every token request, and the token endpoint has no account in
-- hand at the moment it presents a refresh token — it has 32 random bytes. The
-- unguessable secret IS the access control, the same way it is for
-- oidc_clients.client_id; the joins below go through client_row_id and subject,
-- both uuids this service generated.

-- +goose Up

CREATE TABLE oidc_refresh_tokens (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The registration the token was issued to. ON DELETE CASCADE because a
    -- deleted registration's tokens are credentials into nothing, and because
    -- the alternative is a table whose rows reference clients nobody can read.
    client_row_id   uuid        NOT NULL REFERENCES oidc_clients (id) ON DELETE CASCADE,

    -- The user who authenticated. ON DELETE CASCADE for the reason api_keys
    -- gives: a deleted user's credentials are refuse-only rows.
    subject         uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- THE SECRET AT REST. See the header. UNIQUE because it is how the token is
    -- addressed — one indexed equality, no scan — and because a collision would
    -- hand one browser another's refresh token.
    token_digest    text        NOT NULL,

    -- The scopes the token was ISSUED with, not the scopes it may ask for. A
    -- refresh is not an upgrade: the replacement access token carries the
    -- intersection of these with what the registration still allows.
    scopes          text[]      NOT NULL,

    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,

    -- NULL while the token is live. Set by a revocation, and never cleared: a
    -- revoked row stays so an audit can see the credential existed.
    revoked_at      timestamptz,

    -- ROTATION. The first successful presentation claims the row by setting
    -- this, and a second presentation of the same value finds it already set —
    -- which is the reuse signal. It is a timestamp rather than a boolean for
    -- the same reason revoked_at is: "when" is what an incident needs.
    used_at         timestamptz,

    -- The row that replaced this one, once the rotation has happened. It is
    -- what makes a whole FAMILY revocable: reuse detection walks the chain back
    -- to its root, and without the pointer the walk is a scan.
    replaced_by     uuid        REFERENCES oidc_refresh_tokens (id) ON DELETE SET NULL,

    CONSTRAINT oidc_refresh_tokens_digest_length
        CHECK (char_length(token_digest) = 64)
);

CREATE UNIQUE INDEX oidc_refresh_tokens_token_digest_key
    ON oidc_refresh_tokens (token_digest);

-- The family walk's entry point. Partial, because the only rows a walk needs are
-- the live ones: a revoked chain is already revoked and re-walking it would
-- re-revoke what the walk is meant to stop.
CREATE INDEX oidc_refresh_tokens_root_key
    ON oidc_refresh_tokens (replaced_by)
    WHERE replaced_by IS NOT NULL;

-- A sweep of "every live token for this registration" — the client-revocation
-- path — reads by client, so it indexes by client.
CREATE INDEX oidc_refresh_tokens_client_key
    ON oidc_refresh_tokens (client_row_id)
    WHERE revoked_at IS NULL;

-- +goose Down

DROP TABLE oidc_refresh_tokens;
