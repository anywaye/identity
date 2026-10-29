
create or replace function anywaye.credential_tables()
returns table (table_schema text, table_name text, digest_column text)
language sql
stable
as $caf$
  with digest_fn as (
    select fn.oid
      from pg_proc fn
      join pg_namespace fns on fns.oid = fn.pronamespace
     where fns.nspname = 'anywaye'
       and fn.proname = 'current_credential_digest'
       and fn.pronargs = 0
  ),

  resolve as (
    select pol.oid as policy_oid,
           pol.polrelid,
           att.attname as column_name
      from pg_policy pol
      join pg_depend fd
        on fd.classid = 'pg_policy'::regclass
       and fd.objid = pol.oid
       and fd.refclassid = 'pg_proc'::regclass
       and fd.deptype = 'n'
      join digest_fn df on df.oid = fd.refobjid
      left join pg_depend cd
        on cd.classid = 'pg_policy'::regclass
       and cd.objid = pol.oid
       and cd.refclassid = 'pg_class'::regclass
       and cd.refobjid = pol.polrelid
       and cd.refobjsubid > 0
      left join pg_attribute att
        on att.attrelid = pol.polrelid
       and att.attnum = cd.refobjsubid
       and not att.attisdropped
     where pol.polname like '%!_anywaye!_resolve' escape '!'
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
            from resolve
           group by policy_oid, polrelid) g
    join pg_class c on c.oid = g.polrelid
    join pg_namespace n on n.oid = c.relnamespace
   order by n.nspname, c.relname
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