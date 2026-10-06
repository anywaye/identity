-- 00024_user_deletion_set_null.sql — let a person actually leave.
--
-- Four columns name a user with `ON DELETE RESTRICT`, and every one of them is
-- there to protect a record SOMEBODY ELSE OWNS. Between them they decide whether
-- a self-service deletion (`DELETE /v1/me`, migrations' caller
-- `internal/deletion`) can happen at all, and three of the four make it
-- impossible for anybody who has ever done anything.
--
-- This file changes THREE of the four, and the reason each one is different is
-- the most important thing in it. The fourth is left alone, and a test says why.
--
--   CHANGED  account_invitations.invited_by   DROP NOT NULL + SET NULL
--   CHANGED  oidc_clients.created_by          SET NULL
--   CHANGED  oidc_clients.revoked_by          SET NULL, and its pairing CHECK relaxed
--   UNTOUCHED api_keys.revoked_by             unreachable — see the bottom of this file
--
-- # WHY THE RESTRICTS EXISTED, WHICH IS NOT A REASON TO KEEP THEM
--
-- 00007 on `invited_by`: "an invitation outlives the person who sent it — the
-- account still wants the invitee, and silently dropping the invitation because
-- an admin left is not something the account asked for. Deleting a user with
-- pending invitations is therefore refused by the database until they are
-- revoked, which is a later packet."
--
-- THAT LATER PACKET IS THIS ONE, and its answer is not revocation. Revoking is
-- the ACCOUNT OWNER's decision — it withdraws an offer the account still wants to
-- make — and a person deleting their own account has no standing to make it.
-- Cascading would be the other wrong answer, for the reason 00007 already gives.
-- `SET NULL` is the third option and the only one that keeps both facts: THE
-- INVITATION SURVIVES, and the fact of who sent it does not.
--
-- 00009 on `created_by` and `revoked_by`: "A revoked registration is KEPT rather
-- than deleted: an audit of which credentials existed is worth more than a tidier
-- table, and `revoked_at` is what makes the difference readable." A RESTRICT on
-- the creator's id undoes that for precisely the person most likely to want to
-- delete their account: somebody who set up an integration for their team. The
-- registration's own reason for being kept is that it outlives the person who
-- registered it.
--
-- # THIS IS THE SAME ARGUMENT 00022 AND 00012 ALREADY ACCEPTED
--
-- `account_audit_log` carries no foreign key to `accounts`, and `user_audit_log`
-- carries none to `users`, and both files say the same thing: "a cascade is a
-- DELETE, and this table does not delete… the record outlives the person." The
-- two tables that DID keep their foreign keys were not making a different
-- argument; they were making no argument at all, and they inherited `RESTRICT`
-- from the habit of it. `SET NULL` is the same rule expressed on a column that
-- cannot be dropped, because the column is on a row that must be kept.
--
-- # WHAT IS GIVEN UP, STATED PLAINLY
--
-- After this migration the database can no longer answer "who invited this
-- person" or "who registered this client" for a user who has deleted their
-- account. That is a real loss and it is the price of letting somebody leave: the
-- alternative is a service where deleting your account requires the cooperation
-- of every team you were ever on. `identity.user.deleted` carries the user id, and
-- `user_audit_log` carries whatever the operator surface recorded, so the record
-- of the DELETION is intact; what is lost is the attribution on rows that other
-- people own.
--
-- # WHY NOT `ON DELETE CASCADE` ANYWHERE IN THIS FILE
--
-- Because every one of these rows belongs to an ACCOUNT, not to the person. A
-- cascade here would delete a team's OIDC registration because the human who set
-- it up left, and the team's products would stop authenticating with no event
-- their owner could act on.

-- +goose Up

-- # 1. account_invitations.invited_by
--
-- The ONLY column here that is NOT NULL, and it is the one that makes the change
-- more than a verb: `SET NULL` on a `NOT NULL` column is refused by PostgreSQL, so
-- the constraint has to go first. An invitation with no sender is a coherent row —
-- `accepted_by` is the column that matters once it is redeemed, and it is
-- unconstrained (00007), so an accepted invitation already survives its sender
-- being forgotten.
ALTER TABLE account_invitations
    ALTER COLUMN invited_by DROP NOT NULL;

ALTER TABLE account_invitations
    DROP CONSTRAINT account_invitations_invited_by_fkey;

ALTER TABLE account_invitations
    ADD CONSTRAINT account_invitations_invited_by_fkey
    FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE SET NULL;

-- # 2. oidc_clients.created_by
--
-- No NOT NULL to drop, and no CHECK to touch: 00009 pairs `revoked_at` with
-- `revoked_by`, never with `created_by`.
ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_created_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL;

-- # 3. oidc_clients.revoked_by, AND THE CHECK THAT GOES WITH IT
--
-- `oidc_clients_revocation_is_whole` (00009, and named for what it asserts rather
-- than for the columns it touches — it is `api_keys_revocation_is_whole`'s twin)
-- reads
--
--     CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
--
-- which says a revocation and its revoker are set together or not at all. Under
-- `SET NULL` the database must set `revoked_by` to NULL on a row whose
-- `revoked_at` is set, and the old CHECK refuses exactly that — so leaving it
-- would have traded one refusal for another and this migration would appear to
-- work on the fixtures in the tests while failing on the only case that matters.
--
-- The relaxed form says what the table actually means:
--
--     CHECK (revoked_at IS NOT NULL OR revoked_by IS NULL)
--
-- A LIVE registration has no revoker, which is the half the old CHECK was
-- protecting and the half that is a real defect if broken. A REVOKED registration
-- MAY have lost its revoker, which is the half this migration makes reachable.
-- The asymmetry is the whole of it: forgetting who withdrew something must never
-- un-withdraw it, and remembering a revoker on a registration that was never
-- revoked is meaningless rather than dangerous.
--
-- The trigger is untouched, so a revoked registration still cannot be edited back
-- to live by anybody, including a repair script.
ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revocation_is_whole;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revocation_is_whole
    CHECK (revoked_at IS NOT NULL OR revoked_by IS NULL);

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revoked_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revoked_by_fkey
    FOREIGN KEY (revoked_by) REFERENCES users (id) ON DELETE SET NULL;

-- # AND `api_keys.revoked_by` IS DELIBERATELY NOT HERE
--
-- It is `ON DELETE RESTRICT` too, and it looks like the same case. It is not, and
-- the reason is a coincidence in one line of Go: `apikeys.Store.RevokeAllForMember`
-- sets `revoked_by` to the SAME user its WHERE clause filters `user_id` on. So
-- any row referencing a departing person through `revoked_by` is also referencing
-- them through `api_keys_user_id_fkey … ON DELETE CASCADE`, and PostgreSQL removes
-- it through the cascade before the RESTRICT check can see it. The constraint is
-- unreachable.
--
-- `internal/deletion/deletion_rls_test.go`'s `TestARevokedKeyTheUserHeldGoesWithThem`
-- is what measured that, and it is the test that would fail if a path were ever
-- added where one admin revokes a colleague's key — which would make `revoked_by`
-- differ from `user_id` and bring this constraint to life. A migration that
-- changes a constraint nothing can reach is a migration nobody can test, and its
-- CHECK relaxation would be an untested weakening of a security-adjacent
-- invariant.
--
-- Leaving it RESTRICT is also the safe direction: if that path is added, the
-- deletion fails loudly with SQLSTATE 23503 naming this constraint, and whoever
-- adds it reads this paragraph.

-- +goose Down

-- The CHECK first, so the `NOT NULL` that the old form implies cannot be violated
-- by the moment between the two statements. Restoring the pairing before
-- restoring the NOT NULL means no window exists in which a row with `revoked_at`
-- set and `revoked_by` NULL can be written.
--
-- THERE IS A DATA MIGRATION HIDDEN HERE, and it is the honest cost of the Down:
-- rows this Up produced have `revoked_by IS NULL` with `revoked_at` set, and the
-- old CHECK refuses them. There is no value to put back — the person is gone, which
-- is the entire point — so this Down FAILS on such a table rather than inventing
-- an attribution or deleting the row that records a credential which was
-- withdrawn. The same is true of `account_invitations.invited_by`: invitations
-- sent by a since-deleted user cannot have their sender restored.
--
-- That is the expand/contract rule in migrations/README.md arriving from the
-- other direction. Rolling this back is only possible on a deployment where no
-- user has deleted their account since it was applied, which is a statement about
-- when to run it rather than a caveat. `ON DELETE RESTRICT` and the old CHECKs
-- come back in this order: the constraint, then the pairing, then the NOT NULL,
-- which is the reverse of the way they were relaxed and is the only order in
-- which each statement is legal.
ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revoked_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revoked_by_fkey
    FOREIGN KEY (revoked_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revocation_is_whole;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revocation_is_whole
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL));

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_created_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE account_invitations
    DROP CONSTRAINT account_invitations_invited_by_fkey;

ALTER TABLE account_invitations
    ADD CONSTRAINT account_invitations_invited_by_fkey
    FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE RESTRICT;

-- The NOT NULL is restored LAST because it is the statement that fails on rows
-- this migration created, and failing here — after the constraints are already
-- back and the table is exactly as it was — is a clean rollback rather than a
-- half-undone one.
ALTER TABLE account_invitations
    ALTER COLUMN invited_by SET NOT NULL;