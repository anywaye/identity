-- 00025_oauth_provider_microsoft.sql — a third social provider: microsoft.
--
-- The `oauth_provider` enum gains one value, and the value is the whole of this
-- migration. Nothing else about a provider is a database fact: the endpoints are
-- pinned in internal/oauth/endpoints.go, the credentials are environment, and the
-- closed set is knownProviders in internal/oauth/provider.go. The column is the
-- one place a provider name is stored, so it is the one place a new one has to
-- be declared — and it is why this file exists rather than a code change being
-- enough.
--
-- # WHY A NEW MIGRATION AND NOT AN EDIT TO 00008
--
-- 00008 is applied everywhere this service runs. Goose records a version and a
-- checksum per migration and refuses to apply anything after one whose checksum
-- moved, so editing it is not a way to add a value — it is a way to make every
-- existing deployment stop migrating. The rule this tree writes down (and the
-- reason it is repeated here) is: an applied migration is never edited; a new
-- one is written.
--
-- # WHY ONLY MICROSOFT, WHEN THIS PACKET'S TITLE NAMES APPLE TOO
--
-- Apple is scoped out of this packet at the code level, and the enum is code in
-- the same sense the Go list is: `knownProviders` and this column are held
-- together by TestKnownProvidersMatchesTheNamesTheEnumAccepts, which fails on a
-- value in one and not the other. An 'apple' value with no provider behind it
-- would be a name the database accepts and no registry can resolve — a
-- deployment that configured it would serve a 404 for a provider its own schema
-- calls legitimate, and nothing would report the mismatch. Apple's value
-- arrives with Apple's packet, in the same migration that adds the provider.
--
-- # THE TRANSACTION SHAPE, WHICH IS A REAL CONSTRAINT AND NOT A TASTE
--
-- PostgreSQL refuses `ALTER TYPE ... ADD VALUE` inside a transaction block when
-- the new value is then USED in that same transaction (before PG 12 it refused
-- it in a transaction at all). Goose wraps each migration in one. Both facts are
-- fine here and the reason is worth writing down: this migration adds the value
-- and uses nothing, so the restriction never engages. A future migration that
-- added a value and immediately wrote a row with it would have to be split into
-- two, or run outside goose's transaction, and the split is the honest shape —
-- the value becomes visible to the next migration rather than to a write that
-- cannot be rolled back past.
--
-- # WHY THE DOWN REBUILDS THE TYPE INSTEAD OF DROPPING THE VALUE
--
-- PostgreSQL parses `ALTER TYPE ... DROP VALUE` and answers it with 0A000,
-- "dropping an enum value is not implemented". There is no supported way to
-- remove a single enum label; the only route is to recreate the type without
-- it and rewrite every column that uses it — `connected_accounts.provider`
-- and the unique index on (provider, provider_uid) with it — around a copy of
-- the rows. That used to read as "far beyond a rollback's remit", with an
-- empty Down beside it. It is not: `bin/rollback` (and the CI step that runs
-- it) applies each Down and then re-applies the Up, so an empty Down leaves
-- the label behind and the re-apply dies with `enum label "microsoft" already
-- exists`. A rollback-then-redeploy that fails is not a rollback at all — for
-- a real operator as much as for the gate — so the Down does the rebuild.
--
-- The value set in the CREATE TYPE below is positional, not current: when this
-- Down runs, 00026 (apple) has already been rolled back — goose undoes
-- migrations newest-first, and `bin/rollback` replays each migration against
-- the stack its own Up found — so the enum holds exactly google, github and
-- microsoft. A later migration adding a fifth provider does not change what
-- THIS Down must produce.
--
-- Rows naming 'microsoft' refuse loudly rather than vanish: the USING cast
-- errors on a value the new type does not have, so a rollback past live data
-- fails the migration instead of silently deleting rows. The value is additive
-- — no existing row names 'microsoft', and nothing reads it until a provider
-- behind it exists — so the normal case is zero such rows and a clean rebuild.
--
-- The practical consequence, stated rather than hidden: a deployment that has
-- stored 'microsoft' rows and still needs to undo this migration deletes or
-- migrates those rows first, by hand, and the failure names them.

-- +goose Up
ALTER TYPE oauth_provider ADD VALUE 'microsoft';

-- +goose Down

ALTER TYPE oauth_provider RENAME TO oauth_provider_retired;

CREATE TYPE oauth_provider AS ENUM ('google', 'github');

ALTER TABLE connected_accounts
    ALTER COLUMN provider TYPE oauth_provider
    USING provider::text::oauth_provider;

DROP TYPE oauth_provider_retired;
