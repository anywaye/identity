-- 00022_user_audit_log.sql — who turned this person off, and when.
--
-- WHAT THIS TABLE IS. `account_audit_log` (00012) is the house's record of who did
-- what, and it cannot hold a disable. That is not a missing column; it is
-- `account_id NOT NULL` being load-bearing. A disable names NO ACCOUNT, which is
-- DECISIONS.md D14 in one line: `users:disable` is its own scope with no account in
-- its path precisely because its subject is a person rather than one of their
-- memberships, and inventing an account to hang an audit row on would reintroduce
-- the tenancy fiction the scope was built to avoid. A user belongs to as many
-- accounts as they like, so "the caller's own account" would grant that power once
-- per membership — ten tenants, ten chances to disable the same person.
--
-- So this is a second table rather than a widened one, and it is scoped to a user
-- for the same reason the scope is.
--
-- It carries the same discipline as its twin, and every choice below is copied from
-- 00012's header rather than invented here. Where it differs, the difference is
-- written down and the reason is that D14 removes something 00012 had.

-- WHY THERE IS NO FOREIGN KEY ON users, AND THAT IS THE POINT
--
-- A CASCADE is a DELETE, and a DELETE is what the trigger below refuses. The twin
-- states the rule in one line and the reason in a paragraph; the short form is
-- enough here. `ON DELETE CASCADE` would mean deleting a user removes the record of
-- whoever disabled them — which is the shortest possible route from "an operator did
-- something questionable" to "there is no record of it", and it is one statement away.
--
-- THE CONSEQUENCE IS THE SAME ONE THE TWIN ACCEPTED: the rows become unreachable
-- through the API once the user is gone, and they are retained for an operator
-- reading the table directly or importing it elsewhere.

-- WHY THERE IS NO account_id COLUMN AT ALL
--
-- Not NULL-but-unused, not nullable, not present: absent. The packet that asked for
-- this table said it outright, and it is worth restating because it is the one place
-- a future packet will be tempted. A nullable `account_id` is worse than either
-- extreme — it is a column that is supposed to be filled in and never is, so every
-- reader of it has to handle both worlds, and every writer has to decide what the
-- absence means. `tenancy` and `accounts` are keyed by account; a person is not.
-- There is no honest value to put in the column, and a placeholder is a lie the
-- schema then has to be trusted about.

-- WHY NO ROW LEVEL SECURITY AND NO REFERENCES accounts
--
-- `cafaye.protect_table` REFUSES a table with no `account_id` — 00019's header says
-- so, and 00016 declines to protect `accounts` for exactly this reason. So there is
-- no substrate call to make here, and pretending otherwise would mean inventing the
-- account column again one layer down.
--
-- What that costs is worth stating rather than leaving to be discovered: this table
-- has no per-tenant boundary, because there is no tenant in it to enforce one. It is
-- written by the operator surface, whose credential is deployment-wide BY DESIGN (D14:
-- a token holding `users:disable` may name any user on the deployment), and read by
-- whoever holds the application role. Its readers are the operator's, not a tenant's,
-- so a tenant cannot read another's rows here — there are no other tenants' rows here
-- to read. `internal/tenancy`'s `identityTables` deliberately does NOT name this
-- table, and that omission is the decision rather than an oversight.

-- WHY THERE IS NO FOREIGN KEY ON THE ACTORS EITHER
--
-- Copied from the twin's argument, and it is the reason both columns are NOT NULL
-- rather than one being optional: the caller is a machine credential (D14 — a session
-- is refused on these routes before they get here), so there is no human on the other
-- side to record. `actor_key_id` is WHICH api key, which is the id an operator
-- revokes by, and "somebody" is not an answer an incident review can use.
--
-- Neither is a foreign key, so the record outlives both. With `ON DELETE RESTRICT`
-- the audit trail would hold the credential table hostage; with `SET NULL` the record
-- would lose the identity of whoever acted, which is the only part anybody reads.

-- WHAT IS NOT HERE, AND BOTH ABSENCES ARE ARGUED

-- NOT HERE  a CHECK on action. The closed set is a CODE fact — it lives in
--                              internal/useraudit and is validated in Go — for the
--                              reason 00011 gives for api_keys.scopes and 00012 gives
--                              for its own action column: adding an action must not
--                              be a migration. A row holding an action this build
--                              does not know about is refused at the point of use
--                              rather than by the schema.
-- NOT HERE  `affected`      the twin has it because a bulk revocation reports a
--                              count the mutation actually returns. Nothing here
--                              does. `RevokeAllForUser` and
--                              `RevokeAccessTokensForUser` both return an error and
--                              no count, so an `affected` column could only be
--                              filled in with a number somebody estimated — and
--                              internal/admin's Entry doc says exactly why that is
--                              not a thing: it "would let a caller write a record
--                              claiming a count the mutation never reported". When a
--                              sweep starts reporting rows changed, the column and
--                              the CHECK are one statement.
-- NOT HERE  `target`        on the twin it is what makes a bulk row bounded — one
--                              label for a hundred invitations. Here the subject IS
--                              `user_id`, so a target column would be a second way
--                              to say the same thing, and two ways to say it are two
--                              ways to disagree.
-- NOT HERE  the token value nowhere, and never. `api_keys.TokenDigest` is a field on
--                              the struct the handler holds, so a careless
--                              `fmt.Sprintf("%+v", caller.Key)` in an audit path
--                              writes a credential's SHA-256 into a table an operator
--                              reads. The actor is the row's id.

-- +goose Up

CREATE TABLE user_audit_log (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- NO REFERENCES users (id). See the file header: a cascade is a delete, and
    -- this table does not delete.
    --
    -- NOT NULL and no account beside it: a disable is about a person, and a person
    -- is not an account (D14).
    user_id      uuid        NOT NULL,

    -- WHAT HAPPENED, from the closed set in internal/useraudit. Validated in Go, not
    -- here, and a row holding an action this build does not know about is refused at
    -- the point of use rather than by the schema.
    action       text        NOT NULL,

    -- WHO DID IT, as two ids and no more, neither a foreign key. The caller is a
    -- machine credential: there is no user to attribute this to on the other side,
    -- and a record that names nobody is a record with no responsible party.
    actor_user_id uuid       NOT NULL,
    actor_key_id  uuid       NOT NULL,

    -- The request's trace id, so a log line and an audit row can be joined without
    -- either carrying a timestamp comparison.
    trace_id    text        NOT NULL,

    -- The service's clock, passed in like every other timestamp here so the row and
    -- the request that made it agree and only one of the two is under test control.
    occurred_at timestamptz NOT NULL,

    -- 64 is the widest a trace id gets in this service; a longer one means something
    -- is writing a paragraph into an id column.
    CONSTRAINT user_audit_log_trace_id_length
        CHECK (char_length(trace_id) BETWEEN 1 AND 64)
);

-- NO INDEX, and this is a considered absence on 00021's exact argument.
--
-- The twin's index exists because the route that reads it exists. Nothing reads this
-- table yet — the packet that adds the reader adds the index with the query that
-- needs it — and an index is maintained on every INSERT to the table and read by
-- nothing, which is the trade 00021 declined for `disabled_at` and 00002 declined
-- for `locked_until`.
--
-- WHEN THE INDEX LANDS IT IS `(user_id, occurred_at DESC, id DESC)`, because the
-- read order is "what has happened to this user, newest first" and a keyset page over
-- `(occurred_at DESC, id DESC)` needs the index in that order to be a range rather
-- than a sort of the whole table. The cursor must carry `(occurred_at, id)` together:
-- a timestamp-only cursor drops records sharing the boundary instant, and this
-- service's clock makes that the normal case.

-- THE GRANT TO identity_app, and it is TWO PRIVILEGES NOT FOUR.
--
-- 00019 names the tables the application role needs and this is a new one, so it is
-- granted here rather than by a blanket `on all tables` — 00019's second reason for
-- naming them, and the rule still holds. SELECT and INSERT because that is what the
-- service does: write one row, and an audit trail nothing can read is not an audit
-- trail. NOT UPDATE and NOT DELETE, and that is not an oversight to be tidied away —
-- the trigger below refuses both, so granting them would be a privilege whose only
-- possible outcome is an error. A grant should say what the holder may do.

-- +goose StatementBegin
GRANT SELECT, INSERT ON TABLE user_audit_log TO identity_app;
-- +goose StatementEnd

-- THE APPEND-ONLY TRIGGER, which is the actual security property.
--
-- The same shape as `account_audit_log_is_append_only` and the same placement, and
-- 00012's argument is not restated: a service that refuses to UPDATE its own audit
-- rows is a service with a bug-shaped hole in it. The next packet adds an endpoint,
-- or an operator runs a repair script, or somebody connects with psql and fixes a
-- row "just to check", and the trail is editable by the operator whose action is in
-- it. A constraint in Go cannot say that about a psql session.
--
-- It fires on UPDATE and DELETE, never on INSERT, and never on TRUNCATE — a TRUNCATE
-- does not fire row-level triggers, which is how dbtest.Reset can still wipe the
-- table between deliberate runs.
--
-- The StatementBegin/End pair is not decoration: goose splits a migration on
-- semicolons, and a plpgsql body is full of them.
-- +goose StatementBegin
CREATE FUNCTION user_audit_log_is_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'user_audit_log is append-only; % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER user_audit_log_append_only
    BEFORE UPDATE OR DELETE ON user_audit_log
    FOR EACH ROW EXECUTE FUNCTION user_audit_log_is_append_only();

-- +goose Down

-- The order is the reverse of the Up's, and it is deliberate: the trigger goes
-- before the table so the DROP cannot be refused by the rule it depends on. (TRUNCATE
-- would escape the trigger, but DROP TABLE does not.)
--
-- The GRANT is dropped with the table — a grant on a table that no longer exists is
-- already a no-op, so stating it would be noise. What this Down does NOT do is
-- revoke anything from a table that might still have rows worth keeping: the rows
-- go with the table, because that is what a rollback of a migration that created a
-- table means, and because the service that reads them is the one being rolled back.
DROP TRIGGER user_audit_log_append_only ON user_audit_log;
DROP FUNCTION user_audit_log_is_append_only();
DROP TABLE user_audit_log;