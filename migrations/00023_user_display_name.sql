-- 00023_user_display_name.sql — `users.display_name`: what a person is called.
--
-- NULL IS "NO NAME", and there is no default and no backfill: every user row
-- that exists today has no name, because the concept did not exist to give them
-- one. A default of '' would be a SECOND way to say "no name" — the column would
-- then have two representations of one state, and the first person who cleared
-- a name they had set would be the one who found out. This is the same argument
-- as `email_verified_at` in 00014 and `disabled_at` in 00021: a null is a
-- positive statement ("nobody has decided this"), and a zero value would be a
-- lie.
--
-- IT IS NOT AN IDENTIFIER, so there is no unique constraint and no index. A
-- display name is what a human is called, not what anything is looked up by —
-- the email is the identifier and it is the one with the unique index. Two
-- people named "Kaka" are two people, and a unique constraint would be a
-- promise about a lookup that does not happen. The index absence is the same
-- one 00021 argues for `disabled_at`: every door that reads this column has the
-- user row in hand already (it came from the session's user lookup), so an
-- index would be maintained on every write to `users` and read by nothing.
--
-- text, not varchar(n): the length bound is enforced in the handler, where the
-- refusal is a 422 naming the field, and a database CHECK would be a second
-- answer to the same question that can only ever say 500. The account's `name`
-- (00005) is the same shape for the same reason.

-- +goose Up

ALTER TABLE users
    ADD COLUMN display_name text;

-- +goose Down

-- The column goes with it, and the rollback is a rollback of the ENFORCEMENT
-- rather than of the data: the handler that writes the column is deployed
-- after this migration and the one that stops reading it is deployed before it,
-- which is the ordinary expand/contract the prod section of migrations/README.md
-- describes. No row carries a value that outlives the column — a name is
-- re-typed in one request.
ALTER TABLE users
    DROP COLUMN display_name;
