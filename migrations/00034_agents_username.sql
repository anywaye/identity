-- 00034_agents_username.sql — the handle a registration chooses for itself.
--
-- WHY THIS COLUMN EXISTS AT ALL, AND WHY IT WAS NOT IN 00031.
--
-- 00031's "WHAT IS NOT HERE" listed `username` by name and said W1-P2 was the
-- packet that would decide what an agent calls itself beyond its display name.
-- This is that decision, and it turns on one fact about the lifecycle: an
-- UNCLAIMED agent has no account, so a handle that had to be unique PER ACCOUNT
-- (the shape 00031's name column anticipated) would collide on the exact rows
-- that most need to be tellable apart — a dozen self-registrations from a dozen
-- strangers, all with the same account (none).
--
-- So the handle is GLOBALLY UNIQUE, which is also what makes "auto-generate it
-- and retry on conflict" a real behaviour rather than an aspiration: the unique
-- index below is the bound a generated handle runs into and the reason a retry
-- mints another one. Two agents called "Noel" remain two different principals
-- (the display name stays non-unique, exactly as 00031 said it should); it is
-- the HANDLE that must resolve to one.
--
-- WHY GLOBAL UNIQUENESS IS SAFE HERE AND WOULD NOT BE ON AN ACCOUNT SURFACE.
--
-- A globally-unique handle is an enumeration primitive only if a caller can ask
-- "is this handle taken" directly. There is no such route: registration is the
-- only writer, it is rate-limited, and it never answers "that handle is taken" —
-- it either succeeds (the handle is now this agent's) or retries under the hood
-- and succeeds with a different one. A caller who supplies a handle that is
-- already registered finds out the same way everybody does, by a conflict on a
-- value they already held, plus retries.
--
-- The shape is deliberately narrow: lower-case, and if there is a run of
-- non-alphanumerics it collapses to a meaning the registration service produces
-- (base slug, suffix, retries), because a handle goes into logs and a future URL
-- and anything else is a second thing to escape. See the CHECK's failure modes.
-- The DB enforces the SHAPE and the UNIQUENESS; the WRITER (internal/agents)
-- enforces the normalisation, so what reaches the column is already clean.

-- +goose Up

ALTER TABLE agents ADD COLUMN username text;

-- A NULL username is legal in the schema and impossible in practice: every
-- writer in this packet generates one. The nullable column rather than a NOT
-- NULL one, because the rows 00031 could already have written predate the
-- column and a NOT NULL ADD would need a server default nobody chose — the same
-- reason 00031 added its columns nullable rather than defaulted. New
-- registrations always set it; a row with a NULL username is a row this
-- packet's code does not write.
--
-- The shape. lower(username) = username is the case rule stated as a constraint
-- rather than trusted to a writer; the regex is the character rule; the length
-- is the bound. A handle that is one or two characters long, or that starts or
-- ends on a dash, or that carries an underscore or a space, is refused by the
-- database AND by the writer before it, and the two refuse the same set because
-- the CHECK is copied from the writer's shape, not invented beside it.
ALTER TABLE agents ADD CONSTRAINT agents_username_shape CHECK (
    username IS NULL OR (
        char_length(username) BETWEEN 3 AND 39
        AND username = lower(username)
        AND username ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$'
    )
);

-- THE UNIQUE INDEX, and it is what makes retry-on-conflict a real thing. A
-- plain UNIQUE constraint would work; this is written as an INDEX with a
-- partial predicate rather than the constraint syntax for the reason
-- agent_tokens_one_live_name_per_agent is: NULL usernames are the 00031-era rows
-- and Postgres keeps NULLs distinct anyway, so the predicate only documents the
-- live set. lower(username) is the expression so a handle that differs only in
-- case cannot appear twice — and the writer lowercases before it writes, so the
-- expression is belt-and-braces rather than load-bearing.
--
-- The collision this index turns into a retry is a generated 256-bit-adjacent
-- suffix meeting another generated suffix, which is roughly never; the common
-- way to hit it is a caller supplying a handle another caller already
-- registered, and the answer there is a NEW generated handle rather than a
-- "taken" sentence — one answer, and the writer never distinguishes.
CREATE UNIQUE INDEX agents_username_key
    ON agents (lower(username)) WHERE username IS NOT NULL;

-- +goose Down

DROP INDEX agents_username_key;
ALTER TABLE agents DROP CONSTRAINT agents_username_shape;
ALTER TABLE agents DROP COLUMN username;
