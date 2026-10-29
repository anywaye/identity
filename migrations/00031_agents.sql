

-- +goose Up

CREATE TYPE agent_status AS ENUM ('unclaimed', 'claimed', 'disabled');

CREATE TABLE agents (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),

    name        text         NOT NULL,

    status      agent_status NOT NULL DEFAULT 'unclaimed',

    claim_token_digest text,

    claim_link_expires_at timestamptz,

    claimed_by_account_id uuid REFERENCES accounts (id) ON DELETE CASCADE,
    claimed_at            timestamptz,

    device       jsonb        NOT NULL DEFAULT '{}'::jsonb,

    created_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),

    CONSTRAINT agents_claimed_is_whole
        CHECK ((claimed_by_account_id IS NULL) = (claimed_at IS NULL)),

    CONSTRAINT agents_status_and_claim_agree
        CHECK (
            (status = 'unclaimed')
                = (claimed_by_account_id IS NULL AND claim_token_digest IS NULL)
            AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
        ),

    CONSTRAINT agents_claim_link_only_while_unclaimed
        CHECK (status = 'unclaimed' OR claim_token_digest IS NULL),

    CONSTRAINT agents_claim_digest_length
        CHECK (claim_token_digest IS NULL OR char_length(claim_token_digest) = 64),

    CONSTRAINT agents_unclaimed_has_a_live_link
        CHECK (status <> 'unclaimed' OR
               (claim_token_digest IS NOT NULL AND claim_link_expires_at IS NOT NULL)),

    CONSTRAINT agents_name_length
        CHECK (char_length(name) BETWEEN 1 AND 120)
);

CREATE UNIQUE INDEX agents_claim_token_digest_key
    ON agents (claim_token_digest) WHERE claim_token_digest IS NOT NULL;

CREATE INDEX agents_account_idx
    ON agents (claimed_by_account_id, created_at DESC, id DESC)
    WHERE claimed_by_account_id IS NOT NULL;


CREATE TABLE agent_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    agent_id    uuid        NOT NULL REFERENCES agents (id) ON DELETE CASCADE,

    name        text        NOT NULL,

    token_digest text       NOT NULL,

    -- NOT NULL, and the invariant that makes it NOT NULL is the CHECK rather
    -- than a convention in Go: a credential that cannot expire is a permanent
    -- one, and the one place that gets introduced is a future migration adding
    -- a nullable column and a handler that leaves it empty for "no
    -- preference". The same statement api_keys makes, for the same reason.
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    last_used_at timestamptz,

    revoked_at   timestamptz,

    revoked_reason text,

    CONSTRAINT agent_tokens_expires_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT agent_tokens_digest_length
        CHECK (char_length(token_digest) = 64),
    CONSTRAINT agent_tokens_name_length
        CHECK (char_length(name) BETWEEN 1 AND 80),
    CONSTRAINT agent_tokens_reason_only_when_revoked
        CHECK (revoked_at IS NOT NULL OR revoked_reason IS NULL)
);

CREATE UNIQUE INDEX agent_tokens_token_digest_key ON agent_tokens (token_digest);

CREATE INDEX agent_tokens_agent_idx
    ON agent_tokens (agent_id, created_at DESC, id DESC);

CREATE UNIQUE INDEX agent_tokens_one_live_name_per_agent
    ON agent_tokens (agent_id, lower(name)) WHERE revoked_at IS NULL;

CREATE INDEX agent_tokens_expires_at_idx ON agent_tokens (expires_at);


CREATE TABLE agent_events (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    agent_id     uuid        NOT NULL,

    action       text        NOT NULL,

    actor_user_id  uuid,
    actor_token_id uuid,

    trace_id    text        NOT NULL,

    occurred_at timestamptz  NOT NULL,

    CONSTRAINT agent_events_actor_is_whole
        CHECK ((actor_user_id IS NULL) = (actor_token_id IS NULL)),
    CONSTRAINT agent_events_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);

CREATE INDEX agent_events_agent_idx
    ON agent_events (agent_id, occurred_at DESC, id DESC);

-- THE GRANTS, and the two shapes are not interchangeable.
--
-- agents and agent_tokens get SELECT, INSERT and UPDATE because the service
-- writes them (a registration, a claim, a rotation) and mutates them (a
-- disable, a revocation, a last-used write). DELETE is NOT granted, and not as
-- an oversight to tidy away: nothing in this packet deletes an agent or a
-- token, a revocation is an UPDATE, and a privilege whose only possible outcome
-- is an error is not a privilege.
--
-- agent_events gets SELECT and INSERT only, which is the same pair
-- user_audit_log grants for the same reason — the trigger below refuses UPDATE
-- and DELETE, so granting those would be a privilege whose only possible
-- outcome is an error. A grant should say what the holder may do.
-- +goose StatementBegin
grant select, insert, update on table agents to identity_app;
-- +goose StatementEnd
-- +goose StatementBegin
grant select, insert, update on table agent_tokens to identity_app;
-- +goose StatementEnd
-- +goose StatementBegin
grant select, insert on table agent_events to identity_app;
-- +goose StatementEnd

-- THE APPEND-ONLY TRIGGER, which is the actual security property and the same
-- one both twins install. It fires on UPDATE and DELETE, never on INSERT, and
-- never on TRUNCATE — a TRUNCATE does not fire row-level triggers, which is how
-- dbtest.Reset can still wipe the table between deliberate runs.
--
-- The StatementBegin/End pair is not decoration: goose splits a migration on
-- semicolons, and a plpgsql body is full of them.
-- +goose StatementBegin
CREATE FUNCTION agent_events_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'agent_events is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER agent_events_append_only
    BEFORE UPDATE OR DELETE ON agent_events
    FOR EACH ROW EXECUTE FUNCTION agent_events_is_append_only();

-- +goose Down

DROP TRIGGER agent_events_append_only ON agent_events;
DROP FUNCTION agent_events_is_append_only();
DROP TABLE agent_events;
DROP TABLE agent_tokens;
DROP TABLE agents;
DROP TYPE agent_status;
