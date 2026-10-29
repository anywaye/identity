

ALTER TABLE users
    ADD COLUMN is_staff boolean NOT NULL DEFAULT false;


ALTER TABLE users
    DROP COLUMN is_staff;
