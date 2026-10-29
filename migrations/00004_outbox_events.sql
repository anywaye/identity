
-- +goose Up

CREATE TABLE outbox_events (
    id          uuid        PRIMARY KEY,

    type        text        NOT NULL,
    source      text        NOT NULL,
    subject     text,
    occurred_at timestamptz NOT NULL,

    payload     json        NOT NULL,
    envelope    json        NOT NULL,

    published_at timestamptz,
    attempts     integer     NOT NULL DEFAULT 0,
    last_error   text,

    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT outbox_events_type_format CHECK (
        type ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*(\.[a-z][a-z0-9]*(_[a-z0-9]+)*){1,2}$'
    ),
    CONSTRAINT outbox_events_source_format CHECK (
        source ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
    ),

    CONSTRAINT outbox_events_type_length CHECK (char_length(type) BETWEEN 5 AND 120),
    CONSTRAINT outbox_events_source_length CHECK (char_length(source) BETWEEN 2 AND 40),

    CONSTRAINT outbox_events_subject_length CHECK (subject IS NULL OR char_length(subject) BETWEEN 1 AND 200),

    CONSTRAINT outbox_events_attempts_non_negative CHECK (attempts >= 0)
);

CREATE INDEX outbox_events_unpublished_idx ON outbox_events (created_at, id) WHERE published_at IS NULL;

-- +goose Down

DROP TABLE outbox_events;
