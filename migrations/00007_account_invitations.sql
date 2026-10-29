

-- +goose Up

CREATE TYPE account_invitation_role AS ENUM ('admin', 'member');

CREATE TABLE account_invitations (
    id           uuid                      PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   uuid                      NOT NULL,
    email        text                      NOT NULL,
    role         account_invitation_role   NOT NULL,
    token_digest text                      NOT NULL,
    expires_at   timestamptz               NOT NULL,
    accepted_at  timestamptz,
    invited_by   uuid                      NOT NULL,
    created_at   timestamptz               NOT NULL DEFAULT now(),
    updated_at   timestamptz               NOT NULL DEFAULT now(),

    CONSTRAINT account_invitations_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,

    CONSTRAINT account_invitations_invited_by_fkey
        FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE RESTRICT,

    CONSTRAINT account_invitations_email_is_normalized CHECK (email = lower(email)),
    CONSTRAINT account_invitations_email_length CHECK (char_length(email) BETWEEN 3 AND 320),

    CONSTRAINT account_invitations_token_digest_length
        CHECK (char_length(token_digest) = 64),

    CONSTRAINT account_invitations_expires_after_creation
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX account_invitations_token_digest_key ON account_invitations (token_digest);

CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email) WHERE accepted_at IS NULL;

-- +goose Down

DROP INDEX account_invitations_token_digest_key;
DROP TABLE account_invitations;
DROP TYPE account_invitation_role;
