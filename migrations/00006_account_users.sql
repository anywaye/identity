
-- +goose Up

CREATE TABLE account_users (
    account_id uuid          NOT NULL,
    user_id    uuid          NOT NULL,
    role       account_role  NOT NULL,
    created_at timestamptz   NOT NULL DEFAULT now(),
    updated_at timestamptz   NOT NULL DEFAULT now(),

    CONSTRAINT account_users_pkey PRIMARY KEY (account_id, user_id),

    CONSTRAINT account_users_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE,

    CONSTRAINT account_users_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX account_users_user_id_idx ON account_users (user_id);

CREATE INDEX account_users_owners_idx ON account_users (account_id, role);

-- +goose Down

DROP TABLE account_users;
