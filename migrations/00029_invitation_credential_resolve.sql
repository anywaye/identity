
-- +goose Up
select anywaye.protect_credential_table('account_invitations', 'token_digest');

-- +goose Down

DROP POLICY IF EXISTS account_invitations_anywaye_resolve ON account_invitations;
DROP INDEX IF EXISTS account_invitations_anywaye_token_digest_idx;
