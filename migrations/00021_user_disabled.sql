-- 00021_user_disabled.sql — `users.disabled_at`: an account a PERSON turned off.
-- NOT `locked_until`. A lockout is automatic, temporary, and expires by itself —
-- five wrong passwords buy fifteen minutes and the account works again unattended.
-- This is deliberate, indefinite, and set by a human who could have deleted the row.
--
-- NULL IS ACTIVE, and there is no `false`. The column has exactly one non-default
-- state and it is present in the row; a CHECK or a boolean twin would add a second
-- way to say "active" and the two could disagree. This is the same argument as
-- `email_verified_at` in 00014 and `locked_until` in 00002: a null is a positive
-- statement ("nobody has decided this"), and a zero timestamp would be a lie about
-- the epoch.
--
-- NO "WHO" AND NO "WHY" COLUMNS. Deliberately, and the audit log is the answer:
-- `account_audit_log` (00012) is the house's record of who did what, and a pair of
-- columns here would be a second, weaker, deletable copy of it — one an operator
-- could edit with the same `psql` session that a trigger in 00012 already refuses.
-- Two places to record one fact is two places to look, and the one anybody reads
-- is the append-only one.
--
-- IT IS NULL ON EVERY ROW THAT EXISTS TODAY, which is the true state of the world:
-- nobody is disabled in a deployment this migration is landing on, because the
-- concept did not exist to disable them. There is no backfill and no default other
-- than NULL, and there is no data migration — the Down drops the column and
-- returns the service to having no opinion about this at all.

-- +goose Up

ALTER TABLE users
    ADD COLUMN disabled_at timestamptz;

-- NO INDEX, and this one is a considered absence rather than an oversight.
--
-- The question a partial index answers is "every disabled account, oldest first",
-- and nothing in this service asks it. The lockout's columns are unindexed for the
-- same reason and the reason is in 00002: `locked_until` is read on the row the
-- login already fetched by email. `disabled_at` is read the same way — every door
-- that checks it has the user row in hand — so an index would be maintained on
-- every write to `users` and read by nothing. When an operator surface exists to
-- page through disabled accounts, this is one statement, and the packet that adds
-- it adds the index with the query that needs it.
--
-- 00014 got a partial index because the unverified sweep is a query the README
-- documents as forthcoming. There is no such query here.

-- +goose Down

-- The column goes with it.
--
-- A rollback of this file is a rollback of the ENFORCEMENT, not of the data: every
-- door that refused a disabled user is still refusing once this runs, because the
-- refusals read the column and a missing column makes them fail rather than pass.
-- Deploy the code that stops reading it before you roll this back, in that order —
-- which is the ordinary expand/contract the prod section of migrations/README.md
-- describes, and it is worth naming here because this column is read by code that
-- has no compile-time dependency on its existence.
ALTER TABLE users
    DROP COLUMN disabled_at;