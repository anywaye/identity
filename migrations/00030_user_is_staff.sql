-- 00030_user_is_staff.sql — `users.is_staff`: a first-class staff property.
--
-- WHAT IT IS. One boolean on the person, default false, meaning "this user may
-- use the human operator surface" (`/v1/operator/*`: the staff console's
-- directory, status and disable/enable routes). It is deliberately NOT a role,
-- NOT a scope and NOT an account membership: a role is re-read per account on
-- every request and a scope is a capability on a machine credential, while this
-- is a property of the person that a session carries. DECISIONS.md D19 is the
-- entry that revises D14's "no platform-admin role" for it; this file is the
-- column that entry stands on.
--
-- WHY A COLUMN AND NOT A TABLE. The property is read on every authenticated
-- request a staff route serves — `Authenticate` already returns the row — so a
-- join would be a second lookup on the hottest path of the one surface that
-- needs it, for a value with exactly two states. A separate table would also be
-- a second thing to keep consistent with the row it describes; a column cannot
-- disagree with its own row.
--
-- FALSE BY DEFAULT, AND NEVER SELF-SERVICE WRITABLE. No route, no use case and
-- no registration path sets this column: the only writer is
-- `users.Store.SetStaff`, which is called by the `identity-staff` operator
-- command and by nothing in the HTTP surface. A grant that a user could perform
-- on themselves would be a privilege escalation with a nice UI, and a grant
-- through a tenant-admin API would let one tenant mint platform authority.
--
-- NO INDEX, on 00021's exact argument. The column is read on the row the
-- session already fetched by id — every door that checks it has the user in
-- hand — so an index would be maintained on every write to `users` and read by
-- nothing. The staff directory search matches on email and display_name, which
-- is a different query and carries its own trigram reasoning in
-- `users.Store.Search`.
--
-- NO BACKFILL. Every existing row reads false, which is the true state of the
-- world: no deployment has a staff user until an operator grants one, because
-- the grant path did not exist before this migration.

-- +goose Up

ALTER TABLE users
    ADD COLUMN is_staff boolean NOT NULL DEFAULT false;

-- +goose Down

-- The column goes with it. A rollback returns the service to having no staff
-- property at all — which is the fail-closed direction, because every staff
-- route reads the column and a missing column makes them fail rather than pass.
-- Deploy the code that stops reading it before you roll this back, in that
-- order: the ordinary expand/contract in migrations/README.md.
ALTER TABLE users
    DROP COLUMN is_staff;
