

ALTER TABLE users
    ADD COLUMN email_verified_at timestamptz;

CREATE INDEX users_email_unverified_idx
    ON users (created_at)
    WHERE email_verified_at IS NULL;


DROP INDEX users_email_unverified_idx;

ALTER TABLE users
    DROP COLUMN email_verified_at;