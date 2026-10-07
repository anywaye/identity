-- 00029_invitation_credential_resolve.sql — the lookup half of Accept, so a
-- live invitation resolves instead of 404ing.
--
-- WHAT THIS MIGRATION IS. One call: `protect_credential_table` on
-- `account_invitations`, keyed by `token_digest`. That call protects the table
-- exactly as 00016's `protect_table` already did — same four account policies,
-- same ENABLE, same FORCE, same account_id index, all idempotent — and then
-- adds the fifth: one `for select` policy whose qualifier is the digest the
-- caller presented:
--
--     using (token_digest = (select cafaye.current_credential_digest()))
--
-- WHY IT IS THIS CALL AND NOT protect_table AGAIN. The redemption lookup is
-- `WHERE token_digest = $1` with no `account_id` predicate and none it could
-- carry: the account is WHAT THE QUERY IS FOR. Under 00016's account policies
-- alone that query reads zero rows for a request with no identity — the state
-- every redemption is in — and `ErrNoRows` becomes 404 for a live invitation.
-- The site-loop walk proved it with a fresh token in hand. The predicate lives
-- in the POLICY as well as in the caller's query, so the honest semantics are
-- the mechanism's usual narrower-than-nothing: a resolution session may read
-- exactly the invitation row whose digest it presented, and nothing else.
-- `select * from account_invitations` inside one of these sessions returns THAT
-- row, not the table.
--
-- WHAT IT DOES NOT OPEN. `for select` and nothing else, so a resolution
-- session meets the ordinary account policies on the write side with a NULL
-- identity, which is 42501: presenting a token grants no broader read or write
-- scope. A REVOKED row still resolves at the SQL level — the policy carries no
-- revoked_at predicate — because `Store.InvitationByToken` deliberately returns
-- withdrawn rows and lets `Service.Accept` answer the uniform 404; hiding the
-- row here would hide the withdrawal from the account's own admin surface,
-- which reads state rather than redeeming. Expiry is judged against the
-- service clock the use case holds, not the database's now(), for the reason
-- 00028 states: one instant, one implementation.
--
-- THE PAIRED HALF IS IN GO, AND THEY LAND TOGETHER. 00016's header deferred
-- this call with the reason: the migration half alone reads the same zero rows
-- as before, because nothing sets the digest. `Service.Accept` opens its
-- transaction with `tenancy.BeginCredential` before `InvitationByToken`, which
-- is the second half HANDOFF-identity-isolation.md §4.1 names. Both halves or
-- neither.
--
-- WHY IT IS A NEW FILE AND NOT AN EDIT. 00016 is applied in deployed
-- environments; see 00018's header for why the append-only rule holds.

-- +goose Up
select cafaye.protect_credential_table('account_invitations', 'token_digest');

-- +goose Down

-- UNDO THE RESOLUTION AND NOTHING ELSE. Dropping the resolve policy returns a
-- redemption to reading zero rows, which is the 404-every-invitation state this
-- migration fixes — the loud direction, and the safe one for a rollback to
-- land in. The four account policies (00016) are untouched: a Down that removed
-- them would leave the table unprotected rather than restoring the previous
-- boundary. The digest index goes with the policy that needed it.
DROP POLICY IF EXISTS account_invitations_cafaye_resolve ON account_invitations;
DROP INDEX IF EXISTS account_invitations_cafaye_token_digest_idx;
