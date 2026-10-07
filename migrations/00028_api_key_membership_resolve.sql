-- 00028_api_key_membership_resolve.sql — the JOIN half of ByDigest, so a live
-- credential resolves instead of 401ing.
--
-- WHAT THIS MIGRATION IS. One SELECT policy on one table. `api_keys` has
-- resolved by digest since 00016 (`protect_credential_table`), but
-- `apikeys.Store.ByDigest` is `api_keys JOIN account_users`, and the join's
-- other half carried only account/user predicates while the credential
-- transaction sets neither — so the join read zero rows and every live API
-- key answered 401 on introspection (the F2 the site-loop walk proved live,
-- both directions). This policy admits exactly the membership rows the
-- presented credential names, so the unchanged query returns its row again.
--
-- WHY A POLICY AND NOT THE TWO-STEP RESOLVE. The report named both
-- directions; the two-step — read the key under digest scope, then read the
-- role under the account scope the key names — would require the resolution
-- path to set an account identity derived from an unauthenticated read, which
-- breaks the structural property internal/tenancy/credential.go exists to
-- hold (there is no spelling of CredentialResolver that sets an account), and
-- it would split Store.ByDigest's single statement whose four filters
-- deliberately share one ErrNotFound so no caller can tell them apart. The
-- policy keeps the query byte-identical, keeps the GUC discipline (digest
-- only, transaction-local, expired with the transaction), and adds one SELECT
-- policy to one table. No existing policy is touched, FORCE stays on, and
-- there is no SECURITY DEFINER anywhere in the change.
--
-- WHAT THE POLICY SAYS. A session whose digest names a LIVE credential may
-- select the membership rows of that credential's (account, user) pair:
--
--   EXISTS (SELECT 1 FROM api_keys k
--            WHERE k.account_id = account_users.account_id
--              AND k.user_id = account_users.user_id
--              AND k.token_digest = (SELECT cafaye.current_credential_digest())
--              AND k.revoked_at IS NULL)
--
-- The subquery runs under api_keys' own policies, so it can only match the
-- row the caller presented — the resolve policy admits exactly that row, the
-- account policies admit nothing with no account set. `revoked_at IS NULL` is
-- in the policy so a withdrawn credential opens nothing even at the SQL
-- level; the query filters it too. `expires_at` is deliberately NOT here:
-- expiry is judged against the service clock instant ByDigest receives as $2,
-- and duplicating that boundary with the database's now() would make two
-- implementations of one instant (the reason Store.ByDigest documents for
-- taking now as a parameter). An expired-but-unrevoked digest can therefore
-- still read its own membership row inside the transaction — which the query
-- refuses to return, so the application answers nothing, exactly as an
-- account session can read rows it never renders.
--
-- THE PROPERTY THAT SURVIVES. A digest that names no live credential sees no
-- membership row: with no digest set, current_credential_digest() is NULL and
-- the EXISTS is never true; with another credential's digest, only that
-- credential's pair matches. internal/tenancy/credential_join_test.go pins
-- all three — resolves, sees exactly its own membership, revoked resolves
-- nothing — as the application role.
--
-- WHAT THIS SUPERSEDES AND DOES NOT EDIT. 00016's substrate text says a
-- resolution "does not open another table", and credential.go repeats it.
-- That was true of the mechanism then and is narrowed now, deliberately, to
-- the rows above; 00016 is applied in deployed environments and is not
-- edited, so this file states the change and credential.go is updated to
-- point here. The audit stays honest without touching it:
-- cafaye.credential_tables() (00017's OID-based body) lists policies named
-- %_cafaye_resolve that call current_credential_digest(), which is exactly
-- this policy's name and dependency — so account_users appears there with
-- '(unresolved)', reported rather than hidden. membership_tables() matches
-- %_cafaye_members and is unaffected.
--
-- WHY IT IS A NEW FILE AND NOT AN EDIT. 00016 and 00018 are applied in
-- deployed environments; see 00018's header for why the append-only rule
-- holds.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  -- DROP before CREATE, so a re-run converges rather than failing on a
  -- duplicate name — the same discipline the substrate's own functions apply
  -- to every policy they install.
  EXECUTE format('DROP POLICY IF EXISTS %I ON account_users', 'account_users_cafaye_resolve');

  -- The roles are the substrate's two, derived the way protect_table derives
  -- them: the owner running this migration, and that role plus '_app'. A
  -- CREATE POLICY cannot take an expression for a role name, so this is a DO
  -- block rather than a bare statement — and the block is why this section
  -- carries the StatementBegin/End pair goose's semicolon splitter needs.
  EXECUTE format(
    'CREATE POLICY %I ON account_users FOR SELECT TO %I, %I USING (' ||
    'EXISTS (SELECT 1 FROM api_keys k ' ||
    'WHERE k.account_id = account_users.account_id ' ||
    'AND k.user_id = account_users.user_id ' ||
    'AND k.token_digest = (SELECT cafaye.current_credential_digest()) ' ||
    'AND k.revoked_at IS NULL))',
    'account_users_cafaye_resolve', current_user, current_user || '_app');
END
$$;
-- +goose StatementEnd

-- +goose Down

-- UNDO THE MEMBERSHIP HALF AND NOTHING ELSE. Dropping the policy returns a
-- resolution to reading zero membership rows, which is the 401-every-key
-- state this migration fixes — the loud direction, and the safe one for a
-- rollback to land in. The api_keys resolve policy (00016) is untouched: a
-- Down that removed it would blind the credential lookup entirely rather
-- than restoring the previous boundary.
DROP POLICY IF EXISTS account_users_cafaye_resolve ON account_users;
