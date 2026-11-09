-- +goose Up

-- Backfill existing users to the anywaye application. The applications registry
-- and signup_application_id column arrived in 00036, so every row created before
-- that migration has NULL. The shared identity instance served anywaye.com
-- first, so attributing the legacy rows to 'anywaye' is the best available
-- approximation; signups from boat.dev and boax.dev after this column existed
-- carry their own application key.
UPDATE users
SET signup_application_id = (SELECT id FROM applications WHERE key = 'anywaye')
WHERE signup_application_id IS NULL;

-- +goose Down

UPDATE users SET signup_application_id = NULL;
