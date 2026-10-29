
-- +goose Up
-- +goose StatementBegin
-- The body below is VERBATIM from kit's templates/database/tenancy/substrate.sql at
-- kit commit efa49e5, from `create or replace function` through its closing `$caf$;`
-- with nothing inserted between -- not even a comment, because a comment inside the
-- body is a byte difference and `internal/platform/ci/substrate_copy_test.go`
-- compares the two byte for byte. Kit's comment above that function is the argument
-- for it and is not duplicated here on purpose: one argument in one file is a fact,
-- and a second copy of it in this repository is the thing this migration exists to
-- stop.
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- The definition 00016 installed, restored byte for byte.
--
-- THIS IS A ROLLBACK TO A GREEN BOOT, NOT A ROLLBACK TO SAFETY. The body below
-- is the one this migration exists to remove, and it is wrong for the `anywaye`
-- role for the reason in this file's header. It is here because `goose down` has
-- to return the tree to the state the previous migration left it in, and dropping
-- the function instead would turn an audit that lies into one that errors at the
-- call site — a louder failure, but a different schema, and the migration
-- contract is a reversal rather than an improvement.
--
-- If you are reaching for this to fix something, the fix is a forward migration.
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
-- +goose StatementEnd