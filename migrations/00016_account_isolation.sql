-- 00016_account_isolation.sql — the account boundary, enforced by Postgres.
--
-- WHAT THIS MIGRATION IS. The first one in this repository that makes the DATABASE
-- refuse a cross-account read rather than relying on every query remembering its own
-- `where account_id = ?`. Until now the account boundary was entirely in Go: five
-- tables carried `account_id`, every store method passed it, and the whole suite
-- stayed green if one of them stopped. That is one forgotten predicate per query, and
-- nothing but a careful reviewer stands between a typo and one customer reading
-- another's data.
--
-- THE CONTENT BELOW IS kit's `templates/database/tenancy/substrate.sql`, COPIED
-- VERBATIM. Not adapted, not trimmed, not reimplemented: the substrate is the fleet's
-- shared definition of the account boundary, and a service that edited its copy would
-- be a service whose boundary is its own private opinion. kit's README §"Adopting
-- this" step 1 says to copy it; this is that copy. Its own comments explain every
-- decision it makes — the two roles, why `FORCE ROW LEVEL SECURITY` is not optional,
-- why the identity call is wrapped in `(select …)`, and why `current_account_id()`
-- returns NULL rather than raising when no account has been set.
--
-- THE FIVE CALLS AT THE BOTTOM ARE THE WHOLE OF WHAT THIS MIGRATION DECIDES, and
-- `anywaye.protect_table` is the ONLY entry point FOR AN ORDINARILY SCOPED TABLE:
-- there is no `protect_table_lite`, and there is no way to ask it for a policy without
-- FORCE, because a template that offers the weaker version is a template the weaker
-- version gets chosen from.
--
-- There is exactly ONE second entry point, `anywaye.protect_credential_table(table,
-- digest_column)`, and ONE table uses it. It protects a table exactly as `protect_table`
-- does — it CALLS it, so there is no second copy of ENABLE/FORCE to drift — and then
-- adds a fifth `for select` policy whose qualifier is the digest the caller presented.
-- It exists because of a fact about THIS service's authentication, measured on this
-- cluster and written down at the foot of this header: the lookup that turns a presented
-- scoped token into a key has no account to predicate on, because the account is what
-- the lookup is FOR. `protect_table` alone made every scoped token read zero rows, and
-- `ByDigest` maps that to ErrNotFound, so the HTTP layer answered 401 for every valid
-- machine credential in the fleet. The mechanism, and the four answers it rejected (a
-- BYPASSRLS role, a SECURITY DEFINER function, dropping FORCE, leaving the table
-- unprotected), are kit's decision MD24 and the reasoning is in the substrate itself.
--
-- WHY THESE FIVE TABLES, and the method, stated rather than assumed. The list was
-- derived by grepping `account_id` across `migrations/` and then reading each
-- declaration, NOT copied from a document:
--
--   00006_account_users         the membership row. Its primary key is
--                                (account_id, user_id) — the account IS half the key.
--   00007_account_invitations    a pending invitation addressed into an account.
--   00009_oidc_clients          a client's credentials belong to one account.
--   00011_api_keys              a bearer credential. The most consequential row in
--                                the database: this is the token itself.
--   00012_account_audit_log     written once, never updated, but it says who did what
--                                in which account, so reading another account's audit
--                                trail is the disclosure this table exists to prevent.
--
-- The tables DELIBERATELY absent are worth naming, because "not in this migration" is
-- otherwise indistinguishable from "not thought about":
--
--   users, sessions, recovery_tokens, mfa_*      GLOBAL BY CONSTRUCTION. There is no
--       account to scope them by until a request is authenticated, and `users.email`
--       carries a global unique index (00002_users.sql) precisely because login has to
--       find a person before any account is known. Protecting these would be
--       protecting a table that has no account column.
--   connected_accounts          per-USER, not per-account: an external identity link
--       belongs to the person, and one person may hold links under several accounts.
--   accounts                    the account row itself. It is the thing every other
--       table's `account_id` points at, so there is nothing for a policy to filter.
--
-- THE ADOPTION COST, STATED HERE BECAUSE IT WILL SURPRISE SOMEONE. Once a table is
-- protected, the OWNER reads zero rows from it until it sets an identity — FORCE
-- removed the exemption that used to let it through. `protect_table` names the owner in
-- every policy, so the owner's reads are ACCOUNT-SCOPED rather than absent, which is
-- the only version of "the owner may read" that is not "the owner may read
-- everything". A migration that has to read or backfill one of these five tables sets
-- the identity first (`select anywaye.begin_account(…)`), and that is the WHOLE answer.
--
-- There was a second suggestion here and it was WRONG: "or goes through a SECURITY
-- DEFINER function". FORCE ROW LEVEL SECURITY applies to the DEFINER as well as to the
-- invoker, so a SECURITY DEFINER reader of a forced table reads zero rows too, and a
-- migration written to that advice fails SILENTLY rather than loudly. Measured on the
-- real cluster while kit decided MD24. The substrate's own README now says the identity
-- is the whole answer, and this header says it too rather than leaving the false version
-- where the next reader of this file finds it. `api_keys` has one further step: a
-- migration that reads it has no account to begin AS, so it opens the row with
-- `anywaye.begin_credential(<the digest it is looking for>)` — the resolution seam, and
-- the same transaction-local GUC as the account one.
--
-- NO MIGRATION AFTER THIS ONE NEEDS TO KNOW. `anywaye.protect_table` is idempotent —
-- it drops and recreates its policies and uses `create … if not exists` for the index
-- — so a re-run converges rather than failing on a duplicate name.






create schema if not exists anywaye;

create or replace function anywaye.current_account_id()
returns uuid
language plpgsql
stable
as $caf$
declare
  raw text;
begin
  raw := current_setting('anywaye.account_id', true);
  if raw is null or raw = '' then
    return null;
  end if;
  return raw::uuid;
exception
  when invalid_text_representation then
    raise exception 'anywaye.account_id is set to % which is not a uuid', raw
      using errcode = '22023',
            hint = 'anywaye.begin_account/1 takes a uuid. A request that reaches the '
                   'database with a malformed account has a bug in whatever '
                   'authenticated it, and this is the cheapest place to find it.';
end
$caf$;

create or replace function anywaye.begin_account(p_account uuid)
returns void
language plpgsql
as $caf$
begin
  if p_account is null then
    perform set_config('anywaye.account_id', '', true);
    return;
  end if;
  perform set_config('anywaye.account_id', p_account::text, true);
end
$caf$;


create or replace function anywaye.current_credential_digest()
returns text
language plpgsql
stable
as $caf$
declare
  raw text;
begin
  raw := current_setting('anywaye.credential_digest', true);
  if raw is null or raw = '' then
    return null;
  end if;
  return raw;
end
$caf$;

create or replace function anywaye.begin_credential(p_digest text)
returns void
language plpgsql
as $caf$
begin
  if p_digest is null then
    perform set_config('anywaye.credential_digest', '', true);
    return;
  end if;
  perform set_config('anywaye.credential_digest', p_digest, true);
end
$caf$;

create or replace function anywaye.protect_credential_table(
  p_table regclass,
  p_digest_column text,
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
  if p_digest_column is null
     or p_digest_column !~ '^[A-Za-z_][A-Za-z0-9_$]*$' then
    raise exception 'anywaye.protect_credential_table(%, %): the digest column must be one bare column name, and % is not one.', p_table, coalesce(p_digest_column, '<null>'), coalesce(p_digest_column, 'null')
      using errcode = 'undefined_column',
            hint = 'The second argument is the column a caller presents to resolve a credential on this table — `token_digest` for a hashed API key, `token` for a hashed invitation. It is a column of this table and nothing else.';
  end if;

  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = p_digest_column and not attisdropped
  ) then
    raise exception 'anywaye.protect_credential_table(%, %): the table has no % column.', p_table, login_role, p_digest_column
      using errcode = 'undefined_column',
            hint = 'A credential table resolves by the column a caller presents. Name the one this table has; if it has none, this table is not resolved by an unguessable value and does not want this mechanism.';
  end if;

  perform anywaye.protect_table(p_table, p_login_role);

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  execute format('create index if not exists %I on %s (%I)',
                 base || '_anywaye_' || p_digest_column || '_idx', p_table, p_digest_column);

  qual := format('%I = (select anywaye.current_credential_digest())', p_digest_column);

  execute format('drop policy if exists %I on %s', base || '_anywaye_resolve', p_table);
  execute format('create policy %I on %s for select to %I, %I using (%s)',
                 base || '_anywaye_resolve', p_table, current_user, login_role, qual);

  if to_regnamespace('anywaye') is not null then
    execute format('grant usage on schema anywaye to %I', login_role);
  end if;
end
$caf$;

create or replace function anywaye.credential_tables()
returns table (table_schema text, table_name text, digest_column text)
language sql
stable
as $caf$
  select n.nspname::text,
         c.relname::text,
         (regexp_match(
            lower(coalesce(pg_get_expr(p.polqual, p.polrelid), '')),
            '^ *\(?([a-z_][a-z0-9_$]*) = \( *select anywaye\.current_credential_digest\(\)'
          ))[1]::text
    from pg_policy p
    join pg_class c on c.oid = p.polrelid
    join pg_namespace n on n.oid = c.relnamespace
   where p.polname like '%!_anywaye!_resolve' escape '!'
     and p.polcmd = 'r'
     and lower(coalesce(pg_get_expr(p.polqual, p.polrelid), ''))
         like '%anywaye.current_credential_digest()%'
   order by n.nspname, c.relname
$caf$;

create or replace function anywaye.protect_table(
  p_table regclass,
  p_login_role text default null
)
returns void
language plpgsql
as $caf$
declare
  login_role text := coalesce(p_login_role, current_user || '_app');
  qual text := 'account_id = (select anywaye.current_account_id())';
  base text;
  seq_name text;
begin
  if not exists (select 1 from pg_roles where rolname = login_role and rolcanlogin) then
    raise exception 'anywaye.protect_table(%, %): % is not a LOGIN role on this cluster.', p_table, login_role, login_role
      using errcode = 'undefined_object',
            hint = 'kit''s cluster provisions <service> and <service>_app. Either the _app role has not been provisioned — this service was added to KIT_POSTGRES_DATABASES before it existed, and the init script only runs on a fresh volume — or pass the login role explicitly as the second argument.';
  end if;

  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = 'account_id' and not attisdropped
  ) then
    raise exception 'anywaye.protect_table(%, %): the table has no account_id column, so there is nothing to scope it by.', p_table, login_role
      using errcode = 'undefined_column',
            hint = 'Either the column is spelled something else — write the policy yourself and name the fleet''s key — or this table is not account-scoped and should not be protected. A service holding no customer rows is core''s honest zero and needs none of this.';
  end if;

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  execute format('create index if not exists %I on %s (account_id)', base || '_anywaye_account_id_idx', p_table);

  execute format('revoke all on table %s from public', p_table);

  execute format('alter table %s enable row level security', p_table);
  execute format('alter table %s force row level security', p_table);

  execute format('drop policy if exists %I on %s', base || '_anywaye_select', p_table);
  execute format('drop policy if exists %I on %s', base || '_anywaye_insert', p_table);
  execute format('drop policy if exists %I on %s', base || '_anywaye_update', p_table);
  execute format('drop policy if exists %I on %s', base || '_anywaye_delete', p_table);

  execute format('create policy %I on %s for select to %I, %I using (%s)', base || '_anywaye_select', p_table, current_user, login_role, qual);
  execute format('create policy %I on %s for insert to %I, %I with check (%s)', base || '_anywaye_insert', p_table, current_user, login_role, qual);
  execute format('create policy %I on %s for update to %I, %I using (%s) with check (%s)', base || '_anywaye_update', p_table, current_user, login_role, qual, qual);
  execute format('create policy %I on %s for delete to %I, %I using (%s)', base || '_anywaye_delete', p_table, current_user, login_role, qual);

  execute format('grant usage on schema public to %I', login_role);
  if to_regnamespace('anywaye') is not null then
    execute format('grant usage on schema anywaye to %I', login_role);
  end if;
  execute format('grant select, insert, update, delete on table %s to %I', p_table, login_role);

  for seq_name in
    select format('%I.%I', n.nspname, s.relname)
      from pg_class s
      join pg_namespace n on n.oid = s.relnamespace
      join pg_depend d on d.classid = 'pg_class'::regclass
                       and d.refclassid = 'pg_class'::regclass
                       and d.objid = s.oid
                       and d.refobjid = p_table::regclass
      join pg_attribute a on a.attrelid = d.refobjid
                         and a.attnum = d.refobjsubid
     where s.relkind = 'S'
  loop
    execute format('grant usage on sequence %s to %I', seq_name, login_role);
  end loop;
end
$caf$;

create or replace function anywaye.unprotected_tables()
returns table (table_schema text, table_name text, why text)
language sql
stable
as $caf$
  with scoped(nspname) as (
    select 'anywaye'::name
    union
    select n.nspname
      from pg_namespace n
     where n.nspname = 'pg_temp' or left(n.nspname, 8) = 'pg_temp_'
    union
    select n.nspname
      from pg_namespace n
      join pg_class c on c.relnamespace = n.oid
      join pg_policy p on p.polrelid = c.oid
     where c.relkind = 'r'
       and p.polname ~ '_anywaye_(select|insert|update|delete)$'
  )
  select n.nspname::text,
         c.relname::text,
         case
           when not c.relrowsecurity then 'row level security is not enabled'
           when not c.relforcerowsecurity then 'row level security is not FORCED, so the table owner bypasses it'
           when not exists (select 1 from pg_policy p where p.polrelid = c.oid) then 'row level security is enabled with no policy, so every row is hidden'
           else ''
         end
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  left join pg_depend d on d.objid = c.oid and d.deptype = 'e'
  where c.relkind = 'r'
    and d.objid is null
    and n.nspname in (select s.nspname from scoped s)
    and exists (
      select 1 from pg_attribute a
      where a.attrelid = c.oid and a.attname = 'account_id' and not a.attisdropped
    )
    and (
      not c.relrowsecurity
      or not c.relforcerowsecurity
      or not exists (select 1 from pg_policy p where p.polrelid = c.oid)
    )
  order by n.nspname, c.relname
$caf$;



select anywaye.protect_table('account_users');

select anywaye.protect_table('account_invitations');

select anywaye.protect_credential_table('api_keys', 'token_digest');

select anywaye.protect_table('oidc_clients');

select anywaye.protect_table('account_audit_log');


alter table account_users     disable row level security;
alter table account_invitations disable row level security;
alter table oidc_clients      disable row level security;
alter table api_keys          disable row level security;
alter table account_audit_log disable row level security;

drop policy if exists account_users_anywaye_select     on account_users;
drop policy if exists account_users_anywaye_insert     on account_users;
drop policy if exists account_users_anywaye_update     on account_users;
drop policy if exists account_users_anywaye_delete     on account_users;
drop policy if exists account_invitations_anywaye_select on account_invitations;
drop policy if exists account_invitations_anywaye_insert on account_invitations;
drop policy if exists account_invitations_anywaye_update on account_invitations;
drop policy if exists account_invitations_anywaye_delete on account_invitations;
drop policy if exists oidc_clients_anywaye_select      on oidc_clients;
drop policy if exists oidc_clients_anywaye_insert      on oidc_clients;
drop policy if exists oidc_clients_anywaye_update      on oidc_clients;
drop policy if exists oidc_clients_anywaye_delete      on oidc_clients;
drop policy if exists api_keys_anywaye_select          on api_keys;
drop policy if exists api_keys_anywaye_insert          on api_keys;
drop policy if exists api_keys_anywaye_update          on api_keys;
drop policy if exists api_keys_anywaye_delete          on api_keys;
drop policy if exists api_keys_anywaye_resolve         on api_keys;
drop policy if exists account_audit_log_anywaye_select on account_audit_log;
drop policy if exists account_audit_log_anywaye_insert on account_audit_log;
drop policy if exists account_audit_log_anywaye_update on account_audit_log;
drop policy if exists account_audit_log_anywaye_delete on account_audit_log;

drop index if exists account_users_anywaye_account_id_idx;
drop index if exists account_invitations_anywaye_account_id_idx;
drop index if exists oidc_clients_anywaye_account_id_idx;
drop index if exists api_keys_anywaye_account_id_idx;
drop index if exists api_keys_anywaye_token_digest_idx;
drop index if exists account_audit_log_anywaye_account_id_idx;

drop function if exists anywaye.unprotected_tables();
drop function if exists anywaye.protect_credential_table(regclass, text, text);
drop function if exists anywaye.protect_table(regclass, text);
drop function if exists anywaye.begin_account(uuid);
drop function if exists anywaye.begin_credential(text);
drop function if exists anywaye.credential_tables();
drop function if exists anywaye.current_credential_digest();
drop function if exists anywaye.current_account_id();
drop schema if exists anywaye;
