-- +goose Up

CREATE TABLE applications (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    key             text        NOT NULL,

    name            text        NOT NULL,

    kind            text        NOT NULL DEFAULT 'web',

    domain          text        NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),

    created_by      uuid        REFERENCES users (id) ON DELETE RESTRICT,

    CONSTRAINT applications_key_shape
        CHECK (key ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(key) BETWEEN 1 AND 63),

    CONSTRAINT applications_name_length
        CHECK (char_length(name) BETWEEN 1 AND 120),

    CONSTRAINT applications_kind_known
        CHECK (kind IN ('web', 'native', 'm2m', 'service')),

    CONSTRAINT applications_domain_length
        CHECK (char_length(domain) BETWEEN 1 AND 253)
);

CREATE UNIQUE INDEX applications_key_key ON applications (key);

CREATE INDEX applications_domain_idx ON applications (domain);

-- Seed the platform's own applications so they exist from day one.
-- Management (create/update/delete) arrives in a later packet; until then these
-- rows are the registry, edited by migration.
INSERT INTO applications (key, name, kind, domain) VALUES
    ('anywaye', 'Anywaye', 'web', 'anywaye.com'),
    ('boat',    'Boat',    'web', 'boat.dev'),
    ('boax',    'Boax',    'web', 'boax.dev');

-- A user's signup application, when known. Nullable: legacy rows and signups
-- that did not name an application keep NULL, and identity never refuses a
-- signup because of a missing or unknown application key.
ALTER TABLE users
    ADD COLUMN signup_application_id uuid
        REFERENCES applications (id) ON DELETE RESTRICT;

CREATE INDEX users_signup_application_id_idx ON users (signup_application_id);

-- +goose Down

DROP INDEX users_signup_application_id_idx;
ALTER TABLE users DROP COLUMN signup_application_id;

DROP INDEX applications_domain_idx;
DROP INDEX applications_key_key;
DROP TABLE applications;
