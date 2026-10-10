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

> **Re-measured by the second worker (commit `dc6d6c3`), and the counts above are
> wrong: 24 policies live, and the declaration names 22.** Per table:
> `account_audit_log` 4, `account_invitations` 5, `account_users` **6**, `api_keys`
> 5, `oidc_clients` 4 — 24 in `pg_policies`, and exactly the two named below as
> the undeclared pair. The delta of two is unchanged; the totals were a miscount
> (26/25) that survived into this file uncorrected. Also measured, and it is the
> extension of the same method: **no sixth table in `public` has
> `relrowsecurity`**, so there is no third policy hiding anywhere in the database.
> The two below are the whole of the gap.

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

`tenancy.enumeration-partial` names 14 sites. Six are column lists or json tags
(`auditColumns`, `keyColumns`, `clientColumns`, `claimAccount`, and the two
`insert into` column lists); eight are real account-scoped statements. The
mechanism is now measured rather than argued — see below, the paragraph this file
carried about `ATTRIBUTION_WINDOW` was wrong. Narrowing the window is a core
change; folding the eight into `entryPoints` needs three-arm denial fixtures for
`account_users`, `account_invitations`, `api_keys` and `oidc_clients`, which
`internal/tenancy/tenancy_test.go`'s own header explains was declined
deliberately. **A WARN is an honest "I cannot see this", and this one is honest.**

---

# SECOND PASS — `4327889` and `dc6d6c3`

The previous pass finished the packet; this one settled what it left open and
corrected three things in it. `tenancy-check` remains **0 failures, 1 warning
(now 14 sites)**, and `bin/prime` is green (exit 0).

## 1. The attribution mechanism was mis-stated, and the window was never the constraint

The declaration explained the six unattributed statements with
`ATTRIBUTION_WINDOW` — verb and predicate "three to eight lines apart" against a
window of 4. Measured against core's own `scan_file`/`sql_operation`, that is not
the mechanism: `select … from <t>`, `update <t> set` and `delete from <t>` are
matched as **single-line regexes**, so a statement opens only when its verb, its
table and (for an update) its `set` sit on one line. No window size helps a Go
raw string that wraps them. Of every `account_id`-carrying line in the three
original sources, exactly ONE sits under an opening
(`internal/admin/store.go:126`, read back from the site at :127) — which is why
`admin-audit-log-list` is the only entry point that exists. The finding for core
is therefore not "the window should follow the statement" but "a Go raw string
cannot be read line by line at all".

The same measurement found the five `internal/accounts/store.go` statements named
at 286/356/386/593/625 now sit at **310/380/410/819/851** — same operations,
subjects and predicates; the lines had drifted, and a declaration that points at
the wrong line is the defect `check_locations` exists for.

## 2. A fourth source, a real statement in it, and the proof it was missing

Walking the tree for SQL that reaches a protected table found
`internal/oidc/profiles.go` reading `account_users` twice (the personal-account
name and the membership list behind the `accounts` claim) from a file
`scope.sources` did not name. It is now named, and the warning grew from 11 to 14
sites accordingly. `internal/tenancy/profile_read_test.go` proves the read on the
real tables as the app role: **zero rows with no identity** (the state production
actually runs it in — the userinfo path reads through `db.Direct{Pool: pool}`, and
a bare pool carries no GUC), exactly the subject's rows with
`cafaye.begin_user(subject)`, none under another user's identity, none under
another tenant's account identity, and that tenant's own row under its own. Each
zero has a positive control, so none can be narrowness confused with a broken
read. Verdict: **not a tenancy hole** — `account_users_cafaye_members` (00018) and
the four account policies hold it in every state, and the Go predicate is a second
copy of the same bound. It is not an entry point either: the read is scoped by
USER, which the schema cannot express.

## 3. Recorded, deliberately not fixed

That zero-row answer is also a **functional** fact: the `accounts` claim on the
userinfo path is empty in production, and every existing test asserts it through a
fake `ProfileReader`, so nothing has caught it. It is an OIDC packet's surface.
`scope.sources` still names four files and still omits
`internal/accounts/store.go`, for the reason its header gives.

## What core (TG-B1) would have to change — unchanged, plus one

The two widenings above still stand. This pass adds a third, smaller one:
`tenancy.enumeration-partial` reports *every* unclassifiable line, including
column-list constants and json struct tags, because `carries_key` sees the tenancy
key before any statement check runs. A reader is asked to settle fourteen sites
when six of them carry no statement at all. Either skip a line whose only
occurrence of the key is inside a string literal, or report the not-a-statement
class separately — the honest residue and the noise are currently one list.

## Not done, deliberately

- No migration was edited. 00016, 00018, 00028 and 00029 are applied in deployed
  environments, and the measured catalog state agrees with what they write.
- No test was moved or weakened. This pass ADDED one
  (`internal/tenancy/profile_read_test.go`) and corrected the declaration's
  pointers to the three denial arms, which already existed and already passed.
- `scope.sources` still omits `internal/accounts/store.go` and its five
  account-scoped statements, for the reason the header gives: declaring them needs
  three-arm denial fixtures for `account_users`/`account_invitations`, and seeding
  those collides between packages in the shared test database. Now measured rather
  than believed — those five ARE classified by the checker (310/380/410/819/851),
  so naming the file would make five undeclared classified sites and a hard failure;
  the omission keeps the warning honest instead.
- The empty `accounts` claim on the userinfo path is measured and recorded, not
  fixed: it is a functional bug in another packet's surface, and fixing it here
  would mean touching `internal/oidc` beyond what the declaration requires.
