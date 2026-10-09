-- 00033_agent_events_actor_is_at_most_one.sql — the second CHECK in 00031 its own
-- header contradicts.
--
-- THE DEFECT, FOUND BY THE CLAIM'S FIRST INSERT. `agent_events_actor_is_whole` was
-- written
--
--     CHECK ((actor_user_id IS NULL) = (actor_token_id IS NULL))
--
-- which demands the two actor columns move TOGETHER: both NULL or both non-NULL.
-- The comment directly above it says the opposite, and so does the file header:
--
--     -- WHO DID IT. Nullable as a pair ... — a registration has neither,
--     -- a claim has a human, a token rotation has a credential
--     --   actor_user_id  the human whose browser session did it. NOT NULL only
--     --                  when a human did it — a registration is performed by
--     --                  nobody.
--
-- So the three legal shapes are NEITHER, HUMAN ONLY and CREDENTIAL ONLY, and the
-- CHECK forbids the last two. Every event this package can record was refused by
-- the database with `violates check constraint "agent_events_actor_is_whole"`,
-- and the first claim in the service's life failed as a 500.
--
-- This is the SECOND constraint in 00031 to contradict its own header, and it is
-- worth saying plainly what the two have in common: neither was exercised by a
-- single INSERT until the store and the claim landed, because a migration applies
-- cleanly on constraints that are syntactically valid and internally
-- self-contradictory. The store's first test found the first one; the claim use
-- case's first integration test found this one. That is the argument for landing
-- the data layer before any route does, restated in the passive voice of a defect
-- that only a writer can see.
--
-- WHY THIS IS A NEW FILE AND NOT AN EDIT TO 00031. migrations/README.md refuses an
-- edit to an applied migration, for the reason 00032's header gives: the applied
-- databases would disagree with the file on disk and goose would never re-verify.
--
-- WHAT THE FIXED PREDICATE SAYS. AT MOST ONE actor: `actor_user_id IS NULL OR
-- actor_token_id IS NULL`. That permits the three legal shapes and refuses the
-- fourth — a row naming a human AND a credential — which is exactly the half-written
-- record the original comment was reaching for when it said "never one without the
-- other". The comment's instinct was right; its SQL asserted the wrong half of it.
--
-- WHY "AT MOST ONE" AND NOT "EXACTLY ONE". A registration is performed by nobody,
-- and there is no action this package records that must name an actor. Which
-- actions require one is a fact about the ACTION, and 00031's own "WHAT IS NOT
-- HERE" section puts the action vocabulary in Go rather than in the schema: a
-- CHECK that read `action` would make adding an action a migration. So the
-- database refuses the shape that is always wrong and Go's `Event.validate`
-- refuses the rest, which is the same split every other table in this service
-- makes.

-- +goose Up

ALTER TABLE agent_events DROP CONSTRAINT agent_events_actor_is_whole;

ALTER TABLE agent_events ADD CONSTRAINT agent_events_actor_is_whole
    CHECK (actor_user_id IS NULL OR actor_token_id IS NULL);

-- +goose Down

-- The original, defective form. Restoring it makes every event with a single
-- actor unwritable, so the service fails closed rather than wrong — which is the
-- better of the two states for a rollback to return to, and the defect is
-- documented here and in 00031's header rather than being a mystery.
ALTER TABLE agent_events DROP CONSTRAINT agent_events_actor_is_whole;

ALTER TABLE agent_events ADD CONSTRAINT agent_events_actor_is_whole
    CHECK ((actor_user_id IS NULL) = (actor_token_id IS NULL));
