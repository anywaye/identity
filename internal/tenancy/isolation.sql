
begin;

do $preflight$
begin
  if to_regprocedure('anywaye.protect_table(regclass,text)') is null then
    raise exception 'the tenancy substrate is not installed in this database.'
      using errcode = 'undefined_function',
            hint = 'Apply templates/database/tenancy/substrate.sql first.';
  end if;
  if not exists (select 1 from pg_roles where rolname = current_user || '_app' and rolcanlogin) then
    raise exception 'this database has no %_app LOGIN role, so there is no login role to prove anything about.', current_user
      using errcode = 'undefined_object',
            hint = 'kit''s cluster provisions <service> and <service>_app. A service added to KIT_POSTGRES_DATABASES after the volume was created does not get one, because the init script only runs on a fresh volume: recreate the volume, or apply bin/dev db grant.';
  end if;
end
$preflight$;


create or replace function pg_temp.anywaye_assert(
  p_assertion text, p_expected text, p_actual text, p_why text
) returns void
language plpgsql
security definer
as $fn$
declare
  seen text := coalesce(p_actual, '<null>');
begin
  insert into pg_temp.anywaye_probe_result (assertion, expected, actual, verdict, why)
  values (p_assertion, p_expected, seen,
          case when seen = p_expected then 'pass' else 'fail' end, p_why);
end
$fn$;
alter function pg_temp.anywaye_assert(text, text, text, text) owner to current_user;

create or replace function pg_temp.anywaye_observed(p_sql text)
returns text
language plpgsql
as $fn$
begin
  begin
    execute p_sql;
    return 'no error';
  exception
    when others then
      return sqlstate;
  end;
end
$fn$;

create or replace function pg_temp.anywaye_as(p_role text)
returns void
language plpgsql
as $fn$
begin
  execute format('set local role %I', p_role);
end
$fn$;

create or replace function pg_temp.anywaye_alpha() returns uuid
language sql immutable as $fn$ select '11111111-1111-1111-1111-111111111111'::uuid $fn$;

create or replace function pg_temp.anywaye_beta() returns uuid
language sql immutable as $fn$ select '22222222-2222-2222-2222-222222222222'::uuid $fn$;

create temp table pg_temp.anywaye_probe_result (
  assertion text primary key,
  expected text not null,
  actual text not null,
  verdict text not null,
  why text not null
) on commit drop;

create temp table anywaye_probe_things (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null,
  label text not null
) on commit drop;

insert into anywaye_probe_things (account_id, label) values
  (pg_temp.anywaye_alpha(), 'alpha-1'),
  (pg_temp.anywaye_alpha(), 'alpha-2'),
  (pg_temp.anywaye_beta(),  'beta-1');

create temp table anywaye_probe_unprotected (
  id int primary key,
  account_id uuid not null
) on commit drop;

select anywaye.protect_table('pg_temp.anywaye_probe_things');

do $spine$
declare
  r text;
begin
  foreach r in array array['login', 'owner'] loop
    if r = 'login' then
      perform pg_temp.anywaye_as(current_user || '_app');
    else
      perform pg_temp.anywaye_as(current_user);
    end if;

    perform anywaye.begin_account(null);
    perform pg_temp.anywaye_assert(
      r || '/no-identity-reads-no-rows', '0',
      (select count(*)::text from pg_temp.anywaye_probe_things),
      'a request with no account set must see nothing at all: not one tenant, not an error, and not a hint that the table has rows'
    );

    perform anywaye.begin_account(pg_temp.anywaye_beta());
    perform pg_temp.anywaye_assert(
      r || '/another-tenants-rows-read-as-none', '0',
      (select count(*)::text from pg_temp.anywaye_probe_things where account_id = pg_temp.anywaye_alpha()),
      'a request carrying another tenant''s VALID identity must not read that tenant''s rows. This is the assertion an unenforced table fails, and the only one that does'
    );

    perform anywaye.begin_account(pg_temp.anywaye_alpha());
    perform pg_temp.anywaye_assert(
      r || '/own-rows-are-visible', '2',
      (select count(*)::text from pg_temp.anywaye_probe_things where account_id = pg_temp.anywaye_alpha()),
      'a request carrying its own identity must read its own rows. Without this, "reads zero rows" is satisfied by a policy that denies everything'
    );

    perform pg_temp.anywaye_assert(
      r || '/own-identity-reads-only-its-own-rows', '2',
      (select count(*)::text from pg_temp.anywaye_probe_things),
      'an unqualified read as alpha must return alpha''s two rows and not beta''s third: this is what a listing endpoint issues'
    );

    perform anywaye.begin_account(pg_temp.anywaye_beta());
    perform pg_temp.anywaye_assert(
      r || '/another-identity-reads-only-its-own-rows', '1',
      (select count(*)::text from pg_temp.anywaye_probe_things),
      'an unqualified read as beta must return beta''s single row: the other direction of assertion 4'
    );

    reset role;
  end loop;
end
$spine$;

do $writes$
declare
  updated integer;
  deleted integer;
begin
  perform pg_temp.anywaye_as(current_user || '_app');
  perform anywaye.begin_account(pg_temp.anywaye_beta());

  update pg_temp.anywaye_probe_things set label = 'stolen'
    where account_id = pg_temp.anywaye_alpha();
  get diagnostics updated = row_count;
  perform pg_temp.anywaye_assert(
    'login/update-of-another-tenants-row-affects-no-rows', '0', updated::text,
    'an UPDATE aimed at another account''s rows must match nothing. It does not raise — that is the shape of a `using` denial — so the row count is the only thing that says it was refused'
  );

  delete from pg_temp.anywaye_probe_things where account_id = pg_temp.anywaye_alpha();
  get diagnostics deleted = row_count;
  perform pg_temp.anywaye_assert(
    'login/delete-of-another-tenants-row-affects-no-rows', '0', deleted::text,
    'a DELETE aimed at another account''s rows must match nothing'
  );

  reset role;
  perform anywaye.begin_account(pg_temp.anywaye_alpha());

  perform pg_temp.anywaye_assert(
    'login/denied-writes-left-the-other-tenants-rows-intact', 'alpha-1,alpha-2',
    (select string_agg(label, ',' order by label)::text
       from pg_temp.anywaye_probe_things where account_id = pg_temp.anywaye_alpha()),
    'both denied writes must have left the other account''s rows exactly as they were. Read back as alpha, because the role that made the attempt cannot see the rows it was aiming at'
  );

  perform anywaye.begin_account(pg_temp.anywaye_beta());
  perform pg_temp.anywaye_assert(
    'login/own-rows-survive-its-own-writes', 'beta-1',
    (select label::text from pg_temp.anywaye_probe_things where account_id = pg_temp.anywaye_beta()),
    'the denied writes must not have disturbed the caller''s own rows'
  );

  reset role;
end
$writes$;

do $role_half$
declare
  seen text;
begin
  perform pg_temp.anywaye_as(current_user || '_app');

  seen := pg_temp.anywaye_observed(format(
    'insert into pg_temp.anywaye_probe_things (account_id, label) values (%L, %L)',
    pg_temp.anywaye_alpha()::text, 'intruder'));
  reset role;
  perform pg_temp.anywaye_assert(
    'login/insert-into-another-tenants-account-is-refused', '42501', seen,
    'an INSERT naming another account must be refused outright. There is no `using` on an INSERT, so `with check` is the whole boundary, and this is the only cross-tenant write that can raise rather than match nothing');

  perform pg_temp.anywaye_as(current_user || '_app');
  seen := pg_temp.anywaye_observed(
    'alter table pg_temp.anywaye_probe_things disable row level security');
  reset role;
  perform pg_temp.anywaye_assert(
    'login-role/cannot-disable-row-level-security', '42501', seen,
    'the login role must be REFUSED the ability to switch the boundary off. No catalog can report this, and it is the whole reason the login role owns nothing: a role that could disable RLS would need no privilege at all to become unbounded');

  perform pg_temp.anywaye_as(current_user || '_app');
  seen := pg_temp.anywaye_observed(
    'drop policy anywaye_probe_things_anywaye_select on pg_temp.anywaye_probe_things');
  reset role;
  perform pg_temp.anywaye_assert(
    'login-role/cannot-drop-a-policy', '42501', seen,
    'the login role must be REFUSED the ability to remove a policy. A role that could drop a policy needs no privilege at all to become unbounded, and there is no FORCE against it');
end
$role_half$;

select pg_temp.anywaye_assert(
  'login-role/is-not-the-table-owner', 'true',
  (select (pg_get_userbyid(c.relowner) <> current_user || '_app')::text
     from pg_class c where c.oid = 'pg_temp.anywaye_probe_things'::regclass),
  'the login role must not own the table. The two refusals above are the only thing standing between it and every account''s rows, and FORCE does not provide them'
);

do $insert_ok$
begin
  perform pg_temp.anywaye_as(current_user || '_app');
  perform anywaye.begin_account(pg_temp.anywaye_beta());
  insert into pg_temp.anywaye_probe_things (account_id, label)
  values (pg_temp.anywaye_beta(), 'beta-2');
  perform pg_temp.anywaye_assert(
    'login/insert-into-its-own-account-is-allowed', '1',
    (select count(*)::text from pg_temp.anywaye_probe_things where label = 'beta-2'),
    'an INSERT into the caller''s own account must succeed. Without this, the refusal above is satisfied by a policy that refuses every write, which is a state a service reaches by accident when a `with check` is written against the wrong column');
  reset role;
end
$insert_ok$;


select pg_temp.anywaye_assert(
  'policies/name-the-roles', '0',
  (select count(*)::text
     from pg_policy p
    where p.polrelid = 'pg_temp.anywaye_probe_things'::regclass
      and (p.polroles = '{0}'::oid[]
           or not (p.polroles @> ARRAY[
                 (select oid from pg_roles where rolname = current_user || '_app')::oid,
                 (select oid from pg_roles where rolname = current_user)::oid
               ]::oid[]))),
  'every policy must name the login role and the owner explicitly. A policy left at the default is TO PUBLIC, which evaluates it for every role on the cluster'
);

select pg_temp.anywaye_assert(
  'policies/written-for-the-init-plan', '0',
  (select count(*)::text
     from pg_policy p
    where p.polrelid = 'pg_temp.anywaye_probe_things'::regclass
      and strpos(
            replace(replace(replace(
              lower(coalesce(pg_get_expr(p.polqual, p.polrelid), '')
                     || coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')),
              ' ', ''), E'\n', ''), E'\t', ''),
            '(select') = 0),
  'every policy qualifier must wrap the identity call in (select …). A bare call is re-evaluated per candidate row and a subquery is hoisted into an InitPlan and evaluated once per statement: measured on this kit, one call against five on a five-row table'
);


select pg_temp.anywaye_assert(
  'sweep/names-an-unprotected-table', '1',
  (select count(*)::text from anywaye.unprotected_tables()
    where table_name = 'anywaye_probe_unprotected'),
  'anywaye.unprotected_tables() must actually report a table with an account_id column and no policies. If it does not, the assertion below is satisfied by a sweep that reports nothing at all'
);

select pg_temp.anywaye_assert(
  'sweep/every-account-scoped-table-is-protected', '1',
  (select count(*)::text from anywaye.unprotected_tables()),
  'every account-scoped table in this database must be enabled, FORCED and carrying policies. Exactly one is expected to be reported: the control table this file created on purpose'
);

select pg_temp.anywaye_assert(
  'sweep/the-only-finding-is-the-control', 'anywaye_probe_unprotected:row level security is not enabled',
  (select string_agg(table_name || ':' || why, ',')
     from anywaye.unprotected_tables()),
  'the sweep must name the control table and nothing else, with a reason. A sweep that reported a real table as well would mean this file''s own fixture was not protected'
);

select assertion, expected, actual, verdict, why
  from pg_temp.anywaye_probe_result
 order by assertion;