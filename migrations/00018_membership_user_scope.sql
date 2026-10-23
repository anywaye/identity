-- 00018_membership_user_scope.sql — the CALLER, so "which accounts am I in" stops
-- answering with an empty list.
--
-- WHAT THIS MIGRATION IS. `migrations/00016_account_isolation.sql` protects
-- `account_users` with `anywaye.protect_table`, whose predicate is
-- `account_id = (select anywaye.current_account_id())`. That predicate answers
-- "which membership rows belong to the account I am standing in", and the query
-- `GET /v1/accounts` issues is "which accounts is THIS PERSON in" — a question
-- asked before any account is being stood in, because being a caller rather than
-- a tenant is the state you are in until you choose one.
--
-- MEASURED, against this database, as the owner, with the membership row present:
--
--   anywaye.begin_account(…)    rows in account_users visible
--   (not called)               0
--   called with the caller's   1
--   own account
--
-- So the row was there, the join was correct, the query succeeded, and the answer
-- was an empty list. `GET /v1/accounts` returned `[]` to a user who owned an
-- account, and the product rendered "you are not a member of any account". Every
-- assertion in the suite was green while it did this, and that is the whole shape
-- of the defect: it is not a denial, so there is nothing for a suite of denials to
-- catch. 00017's failure was loud — 401, and every scoped-token test red. This one
-- is silent, and "denied" and "you have nothing" are the same response.
--
-- WHY IT IS NOT A LOOSER POLICY, which is the shape this file is tempted into and
-- has to refuse. Every alternative either says something false or undoes 00016:
--
--   * DROP the FORCE, or exempt `identity_app`. Then it is not an account boundary
--     any more, it is a convention, and 00016's entire control (which asserts the
--     OWNER half goes red without FORCE) is the thing being thrown away.
--   * Add a `for select` policy whose USING mentions "the caller" without saying
--     WHICH caller. The policy cannot distinguish one request from another, so it
--     reads every membership row in the database — the credential bug's shape with
--     the digest removed.
--   * A `SECURITY DEFINER` reader. `FORCE` applies to the definer, so it does not
--     work; and kit's MD24 already recorded it as dead for the same reason.
--
-- So the substrate needed to be able to NAME THE CALLER, and naming a caller is
-- what a third transaction-local GUC is for. This migration installs kit's
-- `current_user_id`/`begin_user` pair and its `protect_membership_table` /
-- `membership_tables` pair, byte for byte, and calls the last of them on
-- `account_users`.
--
-- THE BODIES BELOW ARE VERBATIM from kit's
-- `templates/database/tenancy/substrate.sql` at kit master, from `create or
-- replace function` through the closing `$caf$;`, with nothing inserted between —
-- not even a comment, because a comment inside a body is a byte difference and
-- `internal/platform/ci/substrate_copy_test.go` compares the two byte for byte.
-- Kit's comments above each function are the argument for it and are not
-- duplicated here: one argument in one file is a fact, and a second copy of it in
-- this repository is what 00016's drift was.
--
-- WHY IT IS EXACTLY FOUR FUNCTIONS. `protect_membership_table` calls
-- `protect_table`, which is already installed by 00016 and unchanged, so the four
-- new bodies are the complete difference between the substrate this database has
-- and the substrate kit now ships. Re-applying the whole template over a database
-- that already has one would have to be trusted to be a no-op on everything it did
-- not mean to touch.
--
-- WHAT IT DOES NOT CHANGE. No signature, return column or volatility of anything
-- existing changes, so no caller can tell. `CREATE OR REPLACE` on a new signature
-- cannot disturb the OIDs 00016 granted, and `protect_membership_table` calls
-- `protect_table` rather than repeating it, so `account_users` keeps exactly the
-- four account policies it had — same ENABLE, same FORCE, same `account_id`
-- index, same DML grants to `identity_app` — and gains one more. The Go side is a
-- separate change and is NOT in this migration: installing a caller scope nothing
-- calls is inert, and calling it is `accounts.Service.ListMine`'s to make.
--
-- WHY IT IS A NEW FILE AND NOT AN EDIT TO 00016. 00016 has been applied in
-- deployed environments. Editing an applied migration changes the file the next
-- environment applies and not the one the deployed ones ran, which is how two
-- environments holding the same migration count diverge silently.

-- +goose Up
-- +goose StatementBegin
create or replace function anywaye.current_user_id()
returns uuid
language plpgsql
stable
as $caf$
declare
  raw text;
begin
  -- `missing_ok = true` and the empty check are the two cases `begin_account`'s
  -- reader handles, copied rather than re-derived: an unset dotted GUC reads as
  -- set-to-empty, and a caller with no identity is a legitimate state.
  raw := current_setting('anywaye.user_id', true);
  if raw is null or raw = '' then
    return null;
  end if;
  return raw::uuid;
exception
  when invalid_text_representation then
    raise exception 'anywaye.user_id is set to % which is not a uuid', raw
      using errcode = '22023',
            hint = 'anywaye.begin_user/1 takes a uuid. A request that reaches the '
                   'database with a malformed user has a bug in whatever '
                   'authenticated it, and this is the cheapest place to find it.';
end
$caf$;
-- +goose StatementEnd

-- +goose StatementBegin
create or replace function anywaye.begin_user(p_user uuid)
returns void
language plpgsql
as $caf$
begin
  if p_user is null then
    perform set_config('anywaye.user_id', '', true);
    return;
  end if;
  perform set_config('anywaye.user_id', p_user::text, true);
end
$caf$;
-- +goose StatementEnd

-- +goose StatementBegin
create or replace function anywaye.protect_membership_table(
  p_table regclass,
  p_user_column text,
  p_login_role text default null
)
returns void
language plpgsql
as $caf$
declare
  login_role text := coalesce(p_login_role, current_user || '_app');
  base text;
  qual text;
begin
  -- 0. THE COLUMN NAME IS A BARE IDENTIFIER, for the reason
  --    `protect_credential_table`'s check 0 gives: `%I` makes this not about
  --    injection, it is about a typo becoming a policy that quietly admits
  --    nothing instead of a migration that stops.
  if p_user_column is null
     or p_user_column !~ '^[A-Za-z_][A-Za-z0-9_$]*$' then
    raise exception 'anywaye.protect_membership_table(%, %): the user column must be one bare column name, and % is not one.', p_table, coalesce(p_user_column, '<null>'), coalesce(p_user_column, 'null')
      using errcode = 'undefined_column',
            hint = 'The second argument is the column on this table holding the member''s `users.id` — `user_id` in every service kit has shipped. It is a column of this table and nothing else.';
  end if;

  -- 1. AND IT EXISTS, before `protect_table` runs, so a misspelt column cannot
  --    half-install a table. The message quotes the COLUMN rather than the
  --    table, which `protect_credential_table`'s check 1 gets right for a
  --    credential and would get wrong here: `protect_credential_table(%, %)`
  --    interpolates the login role into the second `%` and the table into the
  --    third, which reads as though the role were the missing column. That is a
  --    pre-existing bug in the credential function's message, not something this
  --    one copies.
  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = p_user_column and not attisdropped
  ) then
    raise exception 'anywaye.protect_membership_table(%, %): the table has no % column.', p_table, p_user_column, p_user_column
      using errcode = 'undefined_column',
            hint = 'A membership table is read by the column that names the member. Name the one this table has; if it has none, this table is not a membership table and does not want this mechanism.';
  end if;

  -- 2. THE SAME PROTECTION AS EVERY OTHER ACCOUNT-SCOPED TABLE, from the same
  --    function, so there is no second copy of ENABLE/FORCE to drift. This call
  --    also raises if the table has no `account_id`, which a membership table
  --    must have: it is the edge of the account graph, not a user-scoped
  --    resource that happens to mention accounts.
  perform anywaye.protect_table(p_table, p_login_role);

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  -- 3. THE INDEX ON THE USER COLUMN, for the reason `protect_table` indexes
  --    `account_id`: the policy is evaluated against every candidate row, and
  --    the query this exists for is a scan of the whole table looking for this
  --    caller's memberships. Without the index that scan is sequential however
  --    few rows it returns.
  execute format('create index if not exists %I on %s (%I)',
                 base || '_anywaye_' || p_user_column || '_idx', p_table, p_user_column);

  -- 4. ONE POLICY, FOR ONE COMMAND, FOR THE TWO NAMED ROLES, PREDICATED ON THE
  --    CALLER rather than on an account.
  qual := format('%I = (select anywaye.current_user_id())', p_user_column);

  --    DROP before CREATE, so a re-run converges and a corrected qualifier cannot
  --    survive one.
  execute format('drop policy if exists %I on %s', base || '_anywaye_members', p_table);
  execute format('create policy %I on %s for select to %I, %I using (%s)',
                 base || '_anywaye_members', p_table, current_user, login_role, qual);

  -- 5. USAGE on `anywaye`, for the reason the other two functions grant it:
  --    without it the login role cannot call `anywaye.begin_user/1` and every
  --    membership read fails with `permission denied for schema anywaye` — which
  --    reads as a permissions bug rather than as the missing GRANT that it is.
  if to_regnamespace('anywaye') is not null then
    execute format('grant usage on schema anywaye to %I', login_role);
  end if;
end
$caf$;
-- +goose StatementEnd

-- +goose StatementBegin
create or replace function anywaye.membership_tables()
returns table (table_schema text, table_name text, user_column text)
language sql
stable
as $caf$
  -- (1) The caller function, by OID, with `pronargs = 0` as part of its identity.
  with user_fn as (
    select fn.oid
      from pg_proc fn
      join pg_namespace fns on fns.oid = fn.pronamespace
     where fns.nspname = 'anywaye'
       and fn.proname = 'current_user_id'
       and fn.pronargs = 0
  ),

  -- (2) The policies in the substrate's own naming that call it, with the columns
  --     of THEIR OWN table the call sits beside. Same two dependency joins, same
  --     `deptype`, same `refobjsubid > 0` narrowing of the column match.
  discover as (
    select pol.oid as policy_oid,
           pol.polrelid,
           att.attname as column_name
      from pg_policy pol
      join pg_depend fd
        on fd.classid = 'pg_policy'::regclass
       and fd.objid = pol.oid
       and fd.refclassid = 'pg_proc'::regclass
       and fd.deptype = 'n'
      join user_fn uf on uf.oid = fd.refobjid
      left join pg_depend ud
        on ud.classid = 'pg_policy'::regclass
       and ud.objid = pol.oid
       and ud.refclassid = 'pg_class'::regclass
       and ud.refobjid = pol.polrelid
       and ud.refobjsubid > 0
      left join pg_attribute att
        on att.attrelid = pol.polrelid
       and att.attnum = ud.refobjsubid
       and not att.attisdropped
     where pol.polname like '%!_anywaye!_members' escape '!'
       and pol.polcmd = 'r'
  )

  -- (3) One row per policy, with `'(unresolved)'` when the qualifier names more
  --     than one of the table's own columns — reported, not dropped, for the
  --     reason cost 4 of `credential_tables` above gives.
  select n.nspname::text,
         c.relname::text,
         case when g.columns_named = 1 then g.column_name
              else '(unresolved)' end
    from (select policy_oid,
                 polrelid,
                 count(distinct column_name) as columns_named,
                 min(column_name)            as column_name
            from discover
           group by policy_oid, polrelid) g
    join pg_class c on c.oid = g.polrelid
    join pg_namespace n on n.oid = c.relnamespace
   order by n.nspname, c.relname
$caf$;
-- +goose StatementEnd

-- +goose StatementBegin
-- WHO BELONGS TO WHAT, and who belongs where. The one call.
--
-- It replaces nothing: `protect_membership_table` calls `protect_table` on the
-- same table first, so the four account policies, ENABLE, FORCE, the
-- `account_id` index and the `identity_app` grants are all re-issued exactly as
-- 00016 issued them. The only difference is the fifth policy, whose USING clause
-- is the caller rather than an account:
--
--   using (user_id = (select anywaye.current_user_id()))
--
-- `for select` and nothing else, so a caller who can see where it belongs cannot
-- add itself anywhere: an insert still meets the ordinary `with check`, which
-- demands an account identity. Discovery is not authorisation, and the assertion
-- that holds them apart is `membership/discovery-cannot-write` in kit's
-- isolation.sql, which runs against this table's shape.
--
-- `user_id` is the column 00006 built and every account_users query already keys
-- by. Named here rather than derived, because a substrate that guessed which
-- column holds the member would be guessing at the adopter's vocabulary.
select anywaye.protect_membership_table('account_users', 'user_id');
-- +goose StatementEnd

-- +goose Down

-- UNDO THE CALLER SCOPE AND NOTHING ELSE. The four account policies, ENABLE,
-- FORCE, the `account_id` index and the `identity_app` grants were all there
-- before this migration and are left there, exactly as 00016's own Down leaves the
-- grants: `protect_table` re-issued nothing and changed no privilege, so a Down
-- that revoked them would be undoing 00016 rather than this migration.
--
-- THE DISCOVER POLICY IS NAMED, NOT `cascade`d, for the reason 00016's Down gives
-- and which got worse with this migration: `anywaye.membership_tables()` READS THE
-- POLICIES, so a policy that outlived the capability it describes would keep
-- answering "this table can be read with no account because of who is asking" on a
-- database where it no longer can. An audit that has gone stale is worse than no
-- audit.
-- +goose StatementBegin
drop policy if exists account_users_anywaye_members on account_users;
-- +goose StatementEnd

-- +goose StatementBegin
drop index if exists account_users_anywaye_user_id_idx;
-- +goose StatementEnd

-- THE FOUR FUNCTIONS, NAMED, AND IN THE ORDER THAT LETS THEM GO. `protect_membership_table`
-- calls `protect_table`, and the policy dropped above depends on `current_user_id()`, so
-- the only ordering constraint this list actually carries is: the audit first (it READS
-- the policy), the policy before the function that could recreate it, and the rest in
-- the order they read. Nothing here drops the `anywaye` schema — 00016 created it and
-- 00016's Down removes it, and a migration that dropped it here would take
-- `protect_table` with it and leave 00016's Down unable to finish.
-- +goose StatementBegin
drop function if exists anywaye.membership_tables();
drop function if exists anywaye.protect_membership_table(regclass, text, text);
drop function if exists anywaye.begin_user(uuid);
drop function if exists anywaye.current_user_id();
-- +goose StatementEnd
