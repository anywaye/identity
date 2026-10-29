

ALTER TABLE users
    ADD COLUMN disabled_at timestamptz;



ALTER TABLE users
    DROP COLUMN disabled_at;