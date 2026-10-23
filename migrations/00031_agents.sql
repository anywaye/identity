-- 00031_agents.sql — the agent principal: the thing that exists before anybody
-- owns it.
--
-- THREE TABLES, and they are three because they answer three different questions:
--
--   agents        WHAT EXISTS. A principal with a lifecycle, named by whoever
--                 registered it and bound to a human account by that account's
--                 owner.
--   agent_tokens  WHAT IT MAY DO WITH. Opaque bearer credentials, SHA-256 at
--                 rest, rotatable and revocable.
--   agent_events  WHAT HAPPENED TO IT. Append-only, and no route edits it.
--
-- THE SHAPE OF THE LIFECYCLE, AND WHY IT IS AN ENUM RATHER THAN A BOOLEAN PAIR
--
-- An agent is UNCLAIMED from the moment it registers: it exists, it holds no
-- authority, and nothing it can do depends on a row in `accounts`. A human then
-- claims it, which is the only transition that binds an account — and then it may
-- be DISABLED, which withdraws the binding's effect without deleting the row.
--
-- The previous draft of this file carried `claimed_at`, `claimed_by_account_id`
-- and `disabled_at` as three independent nullable columns and let Go keep them
-- consistent. That is three places to be wrong and one of them is a race. The
-- enum plus the CHECKs below make two illegal states unrepresentable in the
-- schema: an UNCLAIMED agent that remembers an account, and a CLAIMED or
-- DISABLED agent that remembers none.
--
-- WHY THE TRANSITIONS ARE WHAT THEY ARE
--
--   unclaimed → claimed   a HUMAN, authenticated, on the claim screen. This is
--                         the invitation flow's pattern and its whole rigor:
--                         the link is a credential, the click is explicit, and
--                         nothing auto-accepts. Deciding D4.
--   claimed  → disabled   the account's owner turns it off. A disabled agent's
--                         tokens do not resolve — see agent_tokens' resolution
--                         query, which inner-joins the principal.
--   disabled → claimed    re-enabling, by the same owner. NOT a new agent: the
--                         id, the name and the audit trail all survive, which is
--                         the whole reason a disable is not a delete.
--
-- NOT A TRANSITION: unclaimed → disabled. An agent nobody has claimed is a
-- stranger's registration; "disabled" is an act of ownership over something that
-- has no owner yet. The CHECK below refuses it, so a registration that arrives
-- already disabled is a bug at the writer.
--
-- WHAT IS NOT HERE
--
-- NOT HERE  a role, or any authority column. An agent holds tokens, a token
--                          holds scopes, and a scope is resolved against the row
--                          at request time — the same argument internal/apikeys
--                          makes for `api_keys` having no `role` column. A
--                          principal that could answer "what may I do" without a
--                          read is a principal with a stale permission in it.
-- NOT HERE  `username`.        W1-P2 (public registration) is the packet that
--                          decides what an agent calls itself beyond its name,
--                          and a column added now would be filled in with a
--                          default nobody chose. A migration is the cheap part.
-- NOT HERE  row-level security. See below.

-- WHY THERE IS NO `anywaye.protect_table` ON ANY OF THESE THREE
--
-- protect_table refuses a table with no `account_id`, and `agents` cannot have
-- one: an unclaimed agent belongs to nobody, which is the entire point of it.
-- So the substrate call is not available for the table the other two hang off,
-- and 00022's argument covers the consequence rather than being restated here:
-- these tables' boundary is the caller, resolved by the row's own predicate in
-- Go, and there is no per-tenant set of rows in `agents` to keep apart. The
-- claim link is the only value an unauthenticated caller ever presents.
--
-- `claimed_by_account_id` IS NOT AN `account_id`, and the difference is the
-- RLS question. It is NULL for every unclaimed agent, so a policy whose
-- predicate read it would lock out the very rows the claim route exists to
-- serve. It is a reference, not a boundary column.

-- +goose Up

CREATE TYPE agent_status AS ENUM ('unclaimed', 'claimed', 'disabled');

CREATE TABLE agents (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- WHAT THE HUMAN SEES. "Noel", typed by whoever registered the agent and
    -- read on the claim screen and in every audit row about it.
    --
    -- NOT UNIQUE, and deliberately so: two agents called "Noel" in two
    -- deployments are two different principals, and a global unique name would
    -- make the second registration a 409 about a name nobody can see. If a
    -- handle ever needs to be unique it is unique per account, which is a
    -- different constraint on a different column and not this one.
    --
    -- 1..120 characters, matching the CHECK, and the reason it is 120 where
    -- api_keys.name is 80 is that this one is a label for a THING somebody
    -- named rather than for a credential an operator labelled.
    name        text         NOT NULL,

    -- THE LIFECYCLE. See the file header: the enum is the state, and the
    -- CHECKs below are the transitions it is allowed to have made.
    status      agent_status NOT NULL DEFAULT 'unclaimed',

    -- THE CLAIM LINK: a 256-bit opaque value whose DIGEST is stored, exactly as
    -- sessions.token_digest, api_keys.token_digest and
    -- account_invitations.token_digest store theirs. The plaintext exists
    -- exactly once, in the response to the registration that created it, and
    -- there is no column that could hold it afterwards.
    --
    -- WHY THE LINK LIVES ON THE PRINCIPAL AND NOT IN A SIDE TABLE. There is one
    -- live claim link per agent at any instant, and W1-P2's refresh replaces it
    -- in place — which is what "regenerates without claiming" means. A side
    -- table would make that an insert-or-update with a uniqueness rule nobody
    -- needs, and would give the claim route two places to look for the same
    -- fact.
    --
    -- NULL ONCE THE AGENT IS CLAIMED, and the CHECK below is what makes that a
    -- database fact rather than a handler remembering to clear it. A spent
    -- claim link is not a credential; keeping the digest would leave a value
    -- that resolves to a row nobody can redeem again, which is a 404 that
    -- looks like a bug.
    claim_token_digest text,

    -- When the link stops working. NULL means no live link, which is only true
    -- once the agent is claimed. An unclaimed agent ALWAYS has a live link,
    -- enforced by the CHECK rather than by the writer: an unclaimed agent with
    -- no claim link is an agent nobody can ever claim, and it fails silently
    -- for the length of a registration's remaining patience.
    claim_link_expires_at timestamptz,

    -- WHO CLAIMED IT, and when. NULL while unclaimed; NOT NULL from the claim
    -- onwards, including through a disable, because "this agent was claimed by
    -- this account" survives "and then we turned it off".
    --
    -- ON DELETE CASCADE, and the direction is the fail-closed one: an account
    -- that is deleted takes its agents with it, and agent_tokens cascades from
    -- agents, so a credential into a tenant that no longer exists is not a
    -- row that has to be reasoned about by the resolution query. The audit
    -- trail deliberately does NOT cascade — see agent_events.
    claimed_by_account_id uuid REFERENCES accounts (id) ON DELETE CASCADE,
    claimed_at            timestamptz,

    -- WHAT REGISTERED IT. A document rather than four columns, on 00027's
    -- argument: the agent tells us about itself at registration, the values are
    -- read together by the claim screen and written together by the CLI, and
    -- the set of keys is a CODE fact that would otherwise make every new field
    -- a migration. It is never parsed by a route and never filtered on in SQL.
    --
    -- NOT NULL DEFAULT '{}'::jsonb, rather than nullable, because "the agent
    -- told us nothing about itself" is a fact an empty document already says.
    device       jsonb        NOT NULL DEFAULT '{}'::jsonb,

    -- The service's clock, not now(), for the reason every table in this schema
    -- gives: the row and the event announcing it have to agree, and only one of
    -- the two is under test control. The claim link's expiry is measured
    -- against this, so a fake clock parked in the past cannot produce a claim
    -- link that is already expired at insert time (00007's DECISIONS.md D17).
    created_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),

    -- THE CLAIM IS WHOLE OR ABSENT. Two instants, one fact, and a row holding
    -- one without the other is a half-written claim that no reader can
    -- interpret. (claimed_by_account_id IS NULL) is written out rather than
    -- negated so the direction is visible: unclaimed means BOTH are null.
    CONSTRAINT agents_claimed_is_whole
        CHECK ((claimed_by_account_id IS NULL) = (claimed_at IS NULL)),

    -- THE LIFECYCLE AND THE CLAIM AGREE.
    --
    --   unclaimed  →  no account, no instant, and a live claim link
    --   claimed    →  an account, an instant, and no claim link
    --   disabled   →  an account and an instant (it was claimed to be disabled)
    --
    -- The link half is what stops a claimed agent's claim link staying
    -- redeemable: a second click on a spent link must be a 404 rather than a
    -- second claim binding a different account, and the CHECK is the reason it
    -- cannot be anything else.
    CONSTRAINT agents_status_and_claim_agree
        CHECK (
            (status = 'unclaimed')
                = (claimed_by_account_id IS NULL AND claim_token_digest IS NULL)
            AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
        ),

    -- And its inverse, stated on its own rather than folded into the one above
    -- so that a failure names which half is wrong.
    CONSTRAINT agents_claim_link_only_while_unclaimed
        CHECK (status = 'unclaimed' OR claim_token_digest IS NULL),

    -- 64 hex characters, lower case: SHA-256 rendered by hex.EncodeToString,
    -- the same width sessions, api_keys and account_invitations check. The
    -- digest's length is not a secret and an unmatched probe is an ordinary
    -- indexed read either way; the CHECK is here so that a truncated or
    -- mis-encoded digest is a write error rather than a digest that never
    -- matches anything.
    CONSTRAINT agents_claim_digest_length
        CHECK (claim_token_digest IS NULL OR char_length(claim_token_digest) = 64),

    -- An unclaimed agent must carry a live link. This is the check that makes
    -- "registers itself, prints a claim URL, human approves" a property of the
    -- table rather than of the registration route.
    CONSTRAINT agents_unclaimed_has_a_live_link
        CHECK (status <> 'unclaimed' OR
               (claim_token_digest IS NOT NULL AND claim_link_expires_at IS NOT NULL)),

    -- The name is the only free text a stranger chooses here, and it reaches a
    -- log line, a claim screen and an audit row.
    CONSTRAINT agents_name_length
        CHECK (char_length(name) BETWEEN 1 AND 120)
);

-- The claim route's whole query: an equality on a fixed-width hex column, plus
-- the status and the expiry, all of which the CHECKs above have already kept
-- consistent. UNIQUE because a digest that matched two rows would make "which
-- agent did this link claim" unanswerable, and because 256 bits of crypto/rand
-- makes the impossible case an error rather than a nondeterministic claim.
CREATE UNIQUE INDEX agents_claim_token_digest_key
    ON agents (claim_token_digest) WHERE claim_token_digest IS NOT NULL;

-- "Every agent this account has claimed", which is the claim screen's re-visit,
-- the owner's management list, and the index the claim's own read wants when it
-- is asked about an account it has already bound. Newest first so a page is a
-- range rather than a sort.
CREATE INDEX agents_account_idx
    ON agents (claimed_by_account_id, created_at DESC, id DESC)
    WHERE claimed_by_account_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- agent_tokens — the credentials an agent holds.
-- ---------------------------------------------------------------------------
--
-- THE SAME ARGUMENT api_keys MAKES, RESTATED BECAUSE THIS TABLE IS A DIFFERENT
-- LIFETIME RATHER THAN A DIFFERENT HASH. SHA-256 of a 256-bit random value,
-- never the value: argon2id exists to make GUESSING expensive and there is
-- nothing here to guess. What makes a leaked agent token survivable is that it
-- is revocable, that it expires, and that the plaintext was never anywhere for
-- a backup to pick up — which is what the preceding sentence buys.
--
-- ROTATABLE, and the index at the bottom is what makes rotation two requests
-- rather than a transaction that has to find a free name first: a revoked
-- "deploy" and the live one that replaced it coexist, exactly as api_keys'
-- partial index arranges. What is refused is two LIVE tokens with one name on
-- one agent, because "revoke deploy" would then be ambiguous.
--
-- REVOCABLE, and the row is KEPT rather than deleted for the same reason an
-- OIDC registration is kept: "was this withdrawn, or was it always broken?" is a
-- support question and a deleted row answers neither.
--
-- WHAT IS NOT HERE
--
-- NOT HERE  a `scopes` column. The scope vocabulary for an agent token is
-- W1-P2's to declare, one name at a time against a route that exists. A column
--                          now would be filled with a set nobody decided, and a
--                          set nobody decided is a promise about the future
--                          rather than a control over the present.
-- NOT HERE  `revoked_by`.  Nothing human-facing revokes an agent token in this
--                          packet: rotation is the agent replacing its own
--                          credential and a disable is the account's owner
--                          acting on the PRINCIPAL, which cascades through the
--                          resolution query instead. Whoever did it is in
--                          agent_events, where an actor has a type.

CREATE TABLE agent_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- CASCADE: deleting the agent takes its credentials with it. The agent IS
    -- the principal; a token for a principal that no longer exists is a token
    -- that can only ever be refused, and leaving the rows behind would grow
    -- the table for agents that are already gone. api_keys' file header makes
    -- the same argument for its two cascades.
    agent_id    uuid        NOT NULL REFERENCES agents (id) ON DELETE CASCADE,

    -- What the owner calls this credential in a management list and an
    -- incident, for the revocation reason api_keys gives: an operator revokes
    -- by what they can read.
    name        text        NOT NULL,

    -- THE SECRET AT REST: the lower-case hex SHA-256 of the presented value,
    -- whole string including its prefix, so a digest is bound to the format it
    -- was minted in and two credential types can never produce the same digest
    -- for the same random bytes. Nothing on this service compares a digest to
    -- a guess, so the length being public costs nothing.
    token_digest text       NOT NULL,

    -- NOT NULL, and the invariant that makes it NOT NULL is the CHECK rather
    -- than a convention in Go: a credential that cannot expire is a permanent
    -- one, and the one place that gets introduced is a future migration adding
    -- a nullable column and a handler that leaves it empty for "no
    -- preference". The same statement api_keys makes, for the same reason.
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    -- The only column here written on the READ path, and bounded for the reason
    -- api_keys.last_used_at is bounded. The resolution is stated on the column
    -- rather than discovered by somebody who needed the exact second.
    last_used_at timestamptz,

    -- Revocation. Set together or not at all, and the CHECK says so. A revoked
    -- row is KEPT.
    revoked_at   timestamptz,

    -- Why it was withdrawn. NULLABLE, and the empty string is stored as NULL by
    -- the writer, because "no reason given" and "the reason is the empty
    -- string" are not the same fact. Free text and not a closed set: rotation
    -- reasons are typed by whoever rotated.
    revoked_reason text,

    CONSTRAINT agent_tokens_expires_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT agent_tokens_digest_length
        CHECK (char_length(token_digest) = 64),
    CONSTRAINT agent_tokens_name_length
        CHECK (char_length(name) BETWEEN 1 AND 80),
    -- Whole or absent: a revoked_at with no reason is fine (the reason is
    -- optional), but a reason on a LIVE token is a half-written revocation.
    CONSTRAINT agent_tokens_reason_only_when_revoked
        CHECK (revoked_at IS NOT NULL OR revoked_reason IS NULL)
);

-- The resolution query. An equality on a fixed-width hex column, filtered on
-- revoked and expired and joined to the principal's status, so "the agent was
-- disabled" and "the token was revoked" and "the token never existed" are one
-- shape of answer.
CREATE UNIQUE INDEX agent_tokens_token_digest_key ON agent_tokens (token_digest);

-- "Every credential this agent holds", newest first.
CREATE INDEX agent_tokens_agent_idx
    ON agent_tokens (agent_id, created_at DESC, id DESC);

-- ONE LIVE TOKEN PER NAME PER AGENT, partial on the live rows, which is what
-- makes rotation two requests. api_keys' header gives the argument in full.
CREATE UNIQUE INDEX agent_tokens_one_live_name_per_agent
    ON agent_tokens (agent_id, lower(name)) WHERE revoked_at IS NULL;

-- The sweep that removes credentials nobody is going to use again. An index
-- rather than a job, and the same one api_keys carries for the same reason.
CREATE INDEX agent_tokens_expires_at_idx ON agent_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- agent_events — what happened, append-only.
-- ---------------------------------------------------------------------------
--
-- THE SAME DISCIPLINE account_audit_log (00012) and user_audit_log (00022)
-- carry, and every choice below is copied from those two files rather than
-- invented here. Where this one differs, the difference is written down: an
-- agent's history has TWO kinds of actor and neither is a browser session
-- acting alone.
--
-- WHY THERE IS NO FOREIGN KEY ON agents
--
-- A CASCADE is a DELETE, and a DELETE is what the trigger refuses. With ON
-- DELETE CASCADE the account deletion would be blocked by the table recording
-- that the account claimed an agent; with SET NULL the row would lose the only
-- thing anybody reads about it. So the reference is dropped, and what that buys
-- is the property 00012 states in its strongest form: THE CLAIM CANNOT BE
-- UNDONE BY DELETING THE ACCOUNT THAT CLAIMED IT. The rows become unreachable
-- through the API and are retained for an operator reading the table directly.
--
-- WHY THERE IS NO FK ON claimed_by_account_id EITHER
--
-- Same argument, and the consequence is the same one 00012 accepted and stated.
--
-- TWO ACTOR COLUMNS AND NEITHER IS A FOREIGN KEY, for the reason both twins
-- give: with ON DELETE RESTRICT the audit trail holds the credential table
-- hostage, and with SET NULL the record loses the identity of whoever acted,
-- which is the only part anybody reads.
--
--   actor_user_id  the human whose browser session did it. NOT NULL only when
--                  a human did it — a registration is performed by nobody.
--   actor_token_id WHICH credential, when the actor was an agent credential:
--                  the row id of the agent token that made the request. Row id
--                  and never the value: apikeys.Key has a TokenDigest field a
--                  handler holds, and an audit path is exactly where a careless
--                  %+v of it lands.
--
-- WHAT IS NOT HERE
--
-- NOT HERE  the token value  nowhere, and never. The actor is the row's id.
-- NOT HERE  a CHECK on action the closed set is a CODE fact and lives in
--                          internal/agents, for the reason api_keys.scopes and
--                          both twins give: adding an action must not be a
--                          migration.

CREATE TABLE agent_events (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NO REFERENCES agents (id). See the file header: a cascade is a delete,
    -- and this table does not delete.
    agent_id     uuid        NOT NULL,

    -- WHAT HAPPENED, from the closed set in internal/agents. Validated in Go,
    -- not here.
    action       text        NOT NULL,

    -- WHO DID IT. Nullable as a pair and never one without the other — a
    -- registration has neither, a claim has a human, a token rotation has a
    -- credential — and the CHECK says so rather than trusting three writers.
    --
    -- NOT NULL rather than two CHECKs on one line, because "the record names
    -- nobody" and "the record names half a nobody" are the same defect and the
    -- constraint should refuse both.
    actor_user_id  uuid,
    actor_token_id uuid,

    -- The request's trace id, so a log line and an audit row can be joined
    -- without either carrying a timestamp comparison.
    trace_id    text        NOT NULL,

    -- The service's clock, passed in like every other timestamp here, so the
    -- row and the request that made it agree and only one of the two is under
    -- test control.
    occurred_at timestamptz  NOT NULL,

    CONSTRAINT agent_events_actor_is_whole
        CHECK ((actor_user_id IS NULL) = (actor_token_id IS NULL)),
    -- 64 is the widest a trace id gets in this service.
    CONSTRAINT agent_events_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);

-- The read order: "what has happened to this agent, newest first", which is the
-- keyset page over (occurred_at DESC, id DESC) — and the cursor carries both,
-- because a timestamp-only cursor drops records sharing the boundary instant,
-- which this service's clock makes the normal case.
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

-- The order is the reverse of the Up's, and the same order account_audit_log's
-- Down uses: the trigger goes before the table so the DROP cannot be refused by
-- the rule it depends on. The grants go with the table — a grant on a table
-- that no longer exists is already a no-op, so stating them would be noise.
DROP TRIGGER agent_events_append_only ON agent_events;
DROP FUNCTION agent_events_is_append_only();
DROP TABLE agent_events;
DROP TABLE agent_tokens;
DROP TABLE agents;
DROP TYPE agent_status;
