
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
  if p_user_column is null
     or p_user_column !~ '^[A-Za-z_][A-Za-z0-9_$]*$' then
    raise exception 'anywaye.protect_membership_table(%, %): the user column must be one bare column name, and % is not one.', p_table, coalesce(p_user_column, '<null>'), coalesce(p_user_column, 'null')
      using errcode = 'undefined_column',
            hint = 'The second argument is the column on this table holding the member''s `users.id` — `user_id` in every service kit has shipped. It is a column of this table and nothing else.';
  end if;

  if not exists (
    select 1 from pg_attribute
    where attrelid = p_table and attname = p_user_column and not attisdropped
  ) then
    raise exception 'anywaye.protect_membership_table(%, %): the table has no % column.', p_table, p_user_column, p_user_column
      using errcode = 'undefined_column',
            hint = 'A membership table is read by the column that names the member. Name the one this table has; if it has none, this table is not a membership table and does not want this mechanism.';
  end if;

  perform anywaye.protect_table(p_table, p_login_role);

  base := (select c.relname from pg_class c where c.oid = p_table::regclass::oid);

  execute format('create index if not exists %I on %s (%I)',
                 base || '_anywaye_' || p_user_column || '_idx', p_table, p_user_column);

  qual := format('%I = (select anywaye.current_user_id())', p_user_column);

  execute format('drop policy if exists %I on %s', base || '_anywaye_members', p_table);
  execute format('create policy %I on %s for select to %I, %I using (%s)',
                 base || '_anywaye_members', p_table, current_user, login_role, qual);

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
  with user_fn as (
    select fn.oid
      from pg_proc fn
      join pg_namespace fns on fns.oid = fn.pronamespace
     where fns.nspname = 'anywaye'
       and fn.proname = 'current_user_id'
       and fn.pronargs = 0
  ),

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
