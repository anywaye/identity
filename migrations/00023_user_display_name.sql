

ALTER TABLE users
    ADD COLUMN display_name text;


ALTER TABLE users
    DROP COLUMN display_name;
