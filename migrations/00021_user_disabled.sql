
-- +goose Up

ALTER TABLE users
    ADD COLUMN disabled_at timestamptz;


-- +goose Down

ALTER TABLE users
    DROP COLUMN disabled_at;