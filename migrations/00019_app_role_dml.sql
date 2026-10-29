
-- +goose Up
-- +goose StatementBegin
grant select, insert, update, delete on
  table users,
        sessions,
        accounts,
        connected_accounts,
        mfa_credentials,
        mfa_recovery_codes,
        mfa_used_totp_steps,
        mfa_challenges,
        oidc_auth_requests,
        oidc_access_tokens,
        outbox_events,
        recovery_tokens
  to identity_app;
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
revoke select, insert, update, delete on
  table users,
        sessions,
        accounts,
        connected_accounts,
        mfa_credentials,
        mfa_recovery_codes,
        mfa_used_totp_steps,
        mfa_challenges,
        oidc_auth_requests,
        oidc_access_tokens,
        outbox_events,
        recovery_tokens
  from identity_app;
-- +goose StatementEnd