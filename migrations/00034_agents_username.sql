

ALTER TABLE agents ADD COLUMN username text;

ALTER TABLE agents ADD CONSTRAINT agents_username_shape CHECK (
    username IS NULL OR (
        char_length(username) BETWEEN 3 AND 39
        AND username = lower(username)
        AND username ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$'
    )
);

CREATE UNIQUE INDEX agents_username_key
    ON agents (lower(username)) WHERE username IS NOT NULL;


DROP INDEX agents_username_key;
ALTER TABLE agents DROP CONSTRAINT agents_username_shape;
ALTER TABLE agents DROP COLUMN username;
