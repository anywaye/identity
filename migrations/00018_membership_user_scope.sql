
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

select anywaye.protect_membership_table('account_users', 'user_id');


drop policy if exists account_users_anywaye_members on account_users;

drop index if exists account_users_anywaye_user_id_idx;

drop function if exists anywaye.membership_tables();
drop function if exists anywaye.protect_membership_table(regclass, text, text);
drop function if exists anywaye.begin_user(uuid);
drop function if exists anywaye.current_user_id();
