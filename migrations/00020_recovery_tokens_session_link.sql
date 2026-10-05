-- 00020_recovery_tokens_session_link.sql — a fourth purpose on the token machine.
--
-- A DELEGATED SESSION LINK is a token a machine credential mints for one named
-- account, which redeems into the session a password login would have produced.
-- This migration adds its purpose value and NOTHING ELSE: no table, no column, no
-- index, no trigger.
--
-- WHY THAT IS THE WHOLE CHANGE, and it is worth being explicit because the cheap
-- version of this feature is a new `session_links` table with its own mint, expiry
-- and spend logic. Every property a link needs is already a property of this
-- table:
--
--   256 bits of crypto/rand, only the SHA-256 stored      00015, token_digest
--   a deadline every read filters on                      00015, expires_at
--   single use by a conditional UPDATE                    00015, Consume
--   gone with the account it names                        00015, ON DELETE CASCADE
--   unknown / expired / spent / wrong-purpose are one     internal/recovery,
--     answer, so a link cannot be probed                   Store.Live
--
-- A second table would be a second implementation of those five, and the second
-- implementation is where the bug would live. So the machine grows a purpose.
--
-- WHY A MIGRATION AT ALL, given 00015 argues the closed set is a code fact. Both
-- halves of that argument are true and this file is the consequence of the
-- second: `purpose` is NOT a text column with a free-form vocabulary in Go, it is
-- a text column with a CHECK in the schema, and the CHECK is the second opinion
-- that makes a row naming a purpose this build does not implement unwritable. The
-- Go type is the definition; the CHECK is the boundary; widening the vocabulary
-- means touching both, and the boundary is a migration.
--
-- THE DROP FIRST, THEN THE ADD, and the order is load-bearing. Postgres checks a
-- table's CHECK constraints against every existing row, so a single
--
--     ADD CONSTRAINT ... CHECK (purpose IN (..., 'session_link'))
--
-- would re-verify `recovery_tokens` under an ACCESS EXCLUSIVE lock. Dropping the
-- old constraint first and adding the new one in the same transaction releases the
-- table lock once rather than twice, and this table holds live reset tokens: a
-- deploy that waited on it would be a deploy where password resets stop working.
-- Neither statement is CONCURRENTLY-able — a constraint is not an index — so the
-- pair has to share a transaction, which is why this is one file and not two.
--
-- THE FOURTH VALUE IS NOT AN EMAIL CHANGE. `target_email` is NULL here, and
-- 00015's `target_is_for_an_email_change` CHECK
-- ((purpose = 'email_change') = (target_email IS NOT NULL)) refuses the row if it
-- is not: a link row carrying a target would be a row that could confirm an
-- address nobody asked to move. That CHECK needs no edit, and that it needs no
-- edit is the point — the machine's invariants are stated as facts about the table
-- rather than as per-purpose branches.

-- +goose Up

-- +goose StatementBegin
ALTER TABLE recovery_tokens
    DROP CONSTRAINT recovery_tokens_purpose_is_known,
    ADD  CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email', 'session_link'));
-- +goose StatementEnd

-- +goose Down

-- THE REVERSE IS REFUSED WHILE A LINK ROW EXISTS, and that is a fact about
-- Postgres rather than a choice: a table's CHECK is validated against every row
-- when it is added, so dropping the value from the vocabulary while a row names it
-- fails with
--
--   ERROR: check constraint "recovery_tokens_purpose_is_known" of relation
--          "recovery_tokens" is violated by some row (SQLSTATE 23514)
--
-- measured, not predicted — see the commit message. An operator rolling this back
-- therefore has a choice to make, and this file refuses to make it for them:
--
--   DELETE FROM recovery_tokens WHERE purpose = 'session_link';
--
-- first, deliberately, or not at all. Deleting a live link row is destroying a
-- credential, and a rollback that quietly did it would be a side effect dressed as
-- an undo. Rolling back to the build that has no redeem route already makes every
-- outstanding link unusable — nothing can spend them — so the rows can wait for a
-- sweep (the one README.md's "Not built yet" still owes this table) rather than
-- being destroyed by a deploy.
ALTER TABLE recovery_tokens
    DROP CONSTRAINT recovery_tokens_purpose_is_known,
    ADD  CONSTRAINT recovery_tokens_purpose_is_known
        CHECK (purpose IN ('password_reset', 'email_change', 'verify_email'));