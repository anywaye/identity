
DO $$
BEGIN
  EXECUTE format('DROP POLICY IF EXISTS %I ON account_users', 'account_users_anywaye_resolve');

  EXECUTE format(
    'CREATE POLICY %I ON account_users FOR SELECT TO %I, %I USING (' ||
    'EXISTS (SELECT 1 FROM api_keys k ' ||
    'WHERE k.account_id = account_users.account_id ' ||
    'AND k.user_id = account_users.user_id ' ||
    'AND k.token_digest = (SELECT anywaye.current_credential_digest()) ' ||
    'AND k.revoked_at IS NULL))',
    'account_users_anywaye_resolve', current_user, current_user || '_app');
END
$$;


DROP POLICY IF EXISTS account_users_anywaye_resolve ON account_users;
