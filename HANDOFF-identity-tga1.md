# HANDOFF-identity-tga1

Packet TG-A1 — bring `identity` to zero tenancy failures. **Accomplished**:
`tenancy-check .` reports **0 failures, 1 warning**, and `bin/prime` is green.

This file exists for the one piece of residual work that is NOT this packet's
surface: two live row-level-security policies that `identity` cannot declare
because core's checker cannot read them. It is a `core` gap (TG-B1's surface),
and it is written down here so a successor does not rediscover it.

## What is done (commit `452b532`)

| finding | count | fix |
| --- | --- | --- |
| `tenancy.rls-undeclared` | 1 | declared `account_invitations_cafaye_resolve` in `rls.tables` |
| `tenancy.denial-missing` | 3 | moved the three arm lines 324/339/349 → 332/347/357 |
| `tenancy.enumeration-partial` | 1 (WARN) | left, and it is honest — see below |

Verified:

```
$ bash /Users/kaka/Code/any/moon/cafaye/core/harness/bin/tenancy-check .
OK /Users/kaka/Code/any/moon/wt/identity-tga1: 0 failure(s), 1 warning(s) — warnings do not move the exit code
```

```
$ TEST_DATABASE_URL=... ./bin/prime          # 30 packages, `ok`, zero `--- SKIP:`
$ go test -count=1 -v -run 'TestTenancyIdentityOwnsItsFiveTables' ./internal/tenancy/
    --- PASS: TestTenancyIdentityOwnsItsFiveTables/three-way_denial_as_identity_app (0.02s)
    --- PASS: TestTenancyIdentityOwnsItsFiveTables/three-way_denial_as_identity (0.02s)
```

The three arms' lines are `internal/tenancy/tenancy_test.go` 332 / 347 / 357, all
inside `TestTenancyIdentityOwnsItsFiveTables` — **not** `TestTenancyAccountIsolation`,
which is the neighbouring function and the easy one to point at by mistake.

## Residual work — two LIVE policies the declaration cannot name

Measured against the live gate database, not assumed:

```
$ psql "$TEST_DATABASE_URL" -tAc "select tablename, policyname from pg_policies where schemaname='public' order by 1,2"
account_users  account_users_cafaye_members   00018:283
account_users  account_users_cafaye_resolve   00028:92
```

26 policies live on the five protected tables. `rls.tables` names 25. Both gaps
are on `account_users`, both are real, both are `FORCE`d, both bind the
substrate's `identity, identity_app` roles, neither carries BYPASSRLS.

**Why they are not declared.** Each is written through `EXECUTE format(...)`
inside plpgsql, so no line in this tree *begins* `create policy`, and
`_POLICY_STATEMENT` attributes neither to a table. Additionally
`select cafaye.protect_membership_table('account_users', 'user_id')` is a
**third** writer that `_PROTECT_TABLE` does not resolve: it matches
`protect_(credential_)?table`, and `membership_table` is neither.

**Declaring them was tried and it is a false red:**

```
FAIL tenancy.rls-policy-absent: rls.tables names policy 'account_users_cafaye_members'
  on account_users and the migrations do not create it — they write
  ['account_users_cafaye_delete', 'account_users_cafaye_insert',
   'account_users_cafaye_select', 'account_users_cafaye_update']
```

So the honest form is prose. Both are named, located, quoted and explained in
the `rls.tables[account_users]` header in `tenancy.yml`, together with the exact
widening core would need. `rls.tables` keeps the four the checker *can* resolve.

## What core (TG-B1) would have to change, and only that

1. Resolve `cafaye.protect_membership_table('<table>', '<user_column>')` the way
   `protect_credential_table` is already resolved. It delegates to
   `protect_table` for the same four policies and the same two reloptions bits,
   then adds `<table>_cafaye_members`, `for select`,
   `using (<user_column> = (select cafaye.current_user_id()))`. Note the
   predicate is the **caller**, not the account — the same exception, and the
   same reason, as a resolve policy's. The template's own check 1 requires the
   user column to exist, so the call cannot protect a table it is wrong for.
2. Read a `create policy` out of a `format('create policy %I on %s …')` string,
   so a hand-written DO block is not invisible. This is what 00028 uses.

Neither is this packet's surface. `core/harness/tenancy_check.py`,
`core/schemas/*.json` and `core/harness/tenancy_findings.json` were not touched.

## The warning, and why it stays

`tenancy.enumeration-partial` names 11 sites: five are column lists
(`auditColumns`, `clientColumns`, three `insert into` column lists) and six are
real account-scoped statements whose Go raw-string SQL puts the verb and the
predicate 3–8 lines apart while `ATTRIBUTION_WINDOW` is 4. Narrowing the window
is a core change; folding the six into `entryPoints` needs three-arm denial
fixtures for `account_users`, `account_invitations`, `api_keys` and
`oidc_clients`, which `internal/tenancy/tenancy_test.go`'s own header explains
was declined deliberately. **A WARN is an honest "I cannot see this", and this
one is honest.**

## Not done, deliberately

- No migration was edited. 00016, 00018, 00028 and 00029 are applied in deployed
  environments.
- No test was written, moved or weakened. All three denial assertions already
  existed and already passed; only the declaration's pointers were stale.
- `scope.sources` still names three files and still omits
  `internal/accounts/store.go`, for the reason its header gives.
