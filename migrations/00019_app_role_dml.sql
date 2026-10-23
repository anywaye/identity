-- 00019_app_role_dml.sql — the DML `identity_app` needs on the tables NOBODY
-- protected, because the service now logs in as that role.
--
-- WHAT CHANGED, in one line: `docker-compose.yml`'s `DATABASE_URL` went from
-- `identity` to `identity_app`. That is the whole switch, and this migration is
-- what makes the rest of the database agree with it.
--
-- 00016 PROTECTED FIVE TABLES AND GRANTED THEM, which left the grant list
-- looking complete and the service unable to do its job. Measured on the dev
-- cluster, as `identity_app`, immediately after the DSN change:
--
--   $ psql -U identity_app -d identity -c 'select 1 from users'
--   ERROR:  permission denied for table users
--
-- Every table below is a real dependency of the running service — the user a
-- login authenticates, the session it writes, the MFA challenge it raises, the
-- OIDC request it parks, the outbox row it publishes — and none of them is one
-- of the five, so `anywaye.protect_table` never looked at any of them. It is not
-- that the grants are too narrow. They were the only grants that existed, and the
-- service had been running on the OWNER the whole time, where a grant is not
-- needed to reach its own tables.
--
-- WHY THIS IS A MIGRATION AND NOT A GRANT IN THE COMPOSE FILE OR THE INIT
-- SCRIPT. Privileges that the application depends on are schema, and schema
-- belongs in the ordered, reversible, deployed-with-the-code history — the same
-- argument 00016 makes and the same one `bin/migrate` exists for. A GRANT in
-- `docker-compose.yml` would be applied by nothing, on every machine, only when
-- the file was read; a GRANT in kit's `10-cluster.sh` would be a change to a
-- repository that is not this one and is a different change for every adopter.
--
-- WHY THE LIST IS NAMED RATHER THAN `grant … on all tables in schema public`.
-- Two reasons, and the second is the one that matters.
--
--   1. `public` holds `goose_db_version`, which is the migration tool's own
--      bookkeeping table. An application role that can DELETE its own migration
--      history is a role that can make the next `goose up` re-run a migration
--      against a live database.
--   2. The five protected tables are already granted by 00016 and are not named
--      here. A blanket grant would also re-issue those, which is harmless today
--      and is exactly the kind of statement whose scope grows by accident — one
--      `all tables` re-run after a new table lands and the privilege arrives
--      without anybody deciding it should.
--
-- NO SEQUENCES. Every id in these tables is `uuid default gen_random_uuid()`;
-- the only sequence in the schema belongs to `goose_db_version`. Stated because a
-- reader checking this list against the tables will look for the sequences and
-- should find their absence deliberate.
--
-- NO ROW LEVEL SECURITY IS TOUCHED HERE, and no policy is created for any of
-- these tables. That is not a gap. Every one of them is a table with no
-- `account_id`, which is the fleet's own definition of an account-scoped table
-- (D7) and the definition `anywaye.protect_table` enforces by refusing a table
-- without one: 00016 declines to protect `accounts` for precisely this reason.
-- Their boundary is not the account, it is the caller, and the caller's is
-- resolved by the row's own `user_id` predicate in Go (`tenancy.WithUser`) and by
-- the session digest. A policy whose predicate could not be evaluated would make
-- them unreadable to everybody, which is a much harder failure to diagnose than
-- one that says why.
--
-- THE DOWN IS A REAL UNDO, which is the only kind worth having, and it is the
-- shape that makes this migration safe to roll back on a live database: after it
-- runs, the service is broken in an obvious and immediate way (permission denied
-- on `users`), and rolling back restores a state that is equally broken in the
-- same obvious way. Nothing here removes a privilege 00016 granted — 00016's Down
-- does that, and it says why it leaves them.

-- +goose Up
-- +goose StatementBegin
grant select, insert, update, delete on
  table users,
        sessions,
        accounts,
        connected_accounts,
        mfa_credentials,
        mfa_recovery_codes,
        mfa_used_totp_steps,
        mfa_challenges,
        oidc_auth_requests,
        oidc_access_tokens,
        outbox_events,
        recovery_tokens
  to identity_app;
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
revoke select, insert, update, delete on
  table users,
        sessions,
        accounts,
        connected_accounts,
        mfa_credentials,
        mfa_recovery_codes,
        mfa_used_totp_steps,
        mfa_challenges,
        oidc_auth_requests,
        oidc_access_tokens,
        outbox_events,
        recovery_tokens
  from identity_app;
-- +goose StatementEnd