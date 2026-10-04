# REPORT — identity-digest-no-row-flake-01

**Branch** `worker/identity-digest-no-row-flake-01` · **base** identity `master` @ `7799ead`
**Commit** `ad24b24` — *tenancy: the "a digest no row has" case was red one run in sixteen*
**Worktree** `wt-m39-identity-digest-01` · nothing pushed, nothing merged, nothing tagged.

---

## 1. The defect, and the thing it was not

`internal/tenancy/credential_lookup_test.go` built the value for its "a digest no row
has" case inline:

```go
{"a digest no row has", tenantA, digestFor(tenantA)[:63] + "0", 0},
```

`digestFor(tenantID)` is `(accountID + accountID)[:64]` over a 36-character uuid, so the
digest's 64th character is **character 28 of the tenant id**, and `seedCredentialRows`
mints those with `gen_random_uuid()::text`. Character 28 of a uuid is a random hex digit,
so the literal `"0"` the case appends is sometimes already the character sitting there —
and `[:63] + "0"` is then **byte-identical to the row's real digest**.

On those runs the case asks the resolve policy for zero rows for a row that EXISTS. The
policy answers correctly, and the run goes red with a message that reads as a security
failure:

```
credential_lookup_test.go:175: a resolution session presenting 32b0796d… saw 1 rows, want 0.
```

**The production code was never wrong.** That is the finding that shapes everything below,
and it is established rather than argued: see §2 and §5.

## 2. Four independent measurements that it is real

**(a) The observed rate.** 48 consecutive runs of the package against a live Postgres,
**before** the fix: **2 failures** (runs 30 and 38), i.e. 0.042. The manager's independent
measurement was 1 in 24. Two samples, same order of magnitude.

**(b) The rate, over the generator rather than over the test.**
`select count(*) filter (where substr(u,28,1) = '0')` over 200,000 `gen_random_uuid()`s:
**12,641 / 200,000 = 0.06321**. Predicted 1/16 = 0.0625.

**(c) The rate, from inside Go.** The negative control in the new unit test measures the
same thing with the same sampler it uses for the real assertion:
**6,353 / 100,000 = 0.0635** on one run and **6,391 / 100,000 = 0.0639** on another.

**(d) Deterministically, with no randomness at all.** A hand-written tenant id whose
character 28 is `0`, run through both forms in SQL:

```
                                        old_form_equals_real   new_form_equals_real
a1b2c3d4-e5f6-4a8b-9c0d-1e203a4b5c6d            true                    false
```

That is the exact input shape on which the old form reproduced the real digest, and it is
now a **literal in the test suite** (`idWithZeroInCharacter28`), so the shape stops being a
coincidence that has to keep happening.

## 3. What I changed

Four things, in one file. The production policy, the migration and every other test in the
package are untouched.

**1. `digestNoRowHas(real)` replaces the inline expression.** It returns the real digest
with its **first** character replaced by a hex digit chosen to differ from the one it
replaces. Position is *not* what makes this safe — `digestFor` hands the generator every
character of the digest equally. What makes it safe is that the helper **picks** the
replacement and picks it to differ, so the result cannot be the digest it was given
whatever the generator produced. The old form appended a constant and hoped: a probability,
not a property.

**2. The premise is asserted, not assumed.** A case expecting nothing must present a digest
nothing has, so the subtest now compares what it presents against the two digests the seed
wrote — every digest this test creates. It sets no identity and counts nothing, so a
failure there can only be the fixture's, and the message says so instead of arriving later
as a red run that reads like a policy leak. **This converts a 1-in-16 flake into a
deterministic red build**, which is the direction that costs a reviewer's time instead of
the next maintainer's trust in the check.

**3. `writeInResolution` had the same shape and is fixed with the same helper.**
`api_keys_token_digest_key` is a UNIQUE index, so on a colliding run the negative control's
INSERT was refused **by that index rather than by the resolve policy** — it was measuring a
constraint instead of the boundary. It never went red, because all it asserts is that the
insert was not ACCEPTED. A control that is right for two different reasons is evidence of
neither.

**4. `TestTheNoRowDigestIsNeverTheDigestItWasDerivedFrom`** checks the helper with no
database, so a change to the builder fails on every run rather than one in sixteen. Four
hand-written digests (including the literal from (d)) plus 100,000 generated ones, and it
carries a **negative control**: the replaced form is measured with the same sampler in the
same pass and must keep colliding, because a sampler that cannot detect a collision cannot
certify an absence.

The tripwires are untouched: `dsnOrSkip`, `REQUIRED_DB=1` and `TestTheDatabaseTierActuallyRan`
in the other packages are exactly as they were.

## 4. Before and after, with the commands

Live Postgres on `localhost:5432` with identity migrated (version 17). Both
`identity:identity@…` and `identity:cafaye@…` authenticate here; I used the second because
it is what `docker-compose.yml` declares.

```sh
# BEFORE (commit 7799ead)
for i in $(seq 1 48); do
  TEST_DATABASE_URL="postgres://identity:cafaye@localhost:5432/identity?sslmode=disable" \
    go test -count=1 -run TestTenancyACredentialResolves ./internal/tenancy/
done
# => 2 failures in 48 runs (0.042)

# AFTER (commit ad24b24), two batches
for i in $(seq 1 96); do
  TEST_DATABASE_URL="postgres://identity:cafaye@localhost:5432/identity?sslmode=disable" \
    go test -count=1 -run TestTenancyACredentialResolves ./internal/tenancy/
done
# => 0 failures in 96 runs
```

| | runs | failures | rate |
|---|---|---|---|
| before | 48 | **2** | 0.042 |
| after | 96 | **0** | 0 |
| after, with `-race` | 5 | **0** | 0 |

**The forced-digest demonstration the brief asked for, with nothing random in it.** A fixed
fixture row whose digest ends in `0`, probed in three transactions (`forced-digest-demo.sql`):

| probe | presented | rows seen | correct answer |
|---|---|---|---|
| A | the digest the row HAS | **1** | 1 |
| B | the **old** fixture form, `[:63]+"0"` — byte-identical to A | **1** | 1 |
| C | the **new** form, `"0"||real[2:]` | **0** | 0 |

Probe B is the whole packet in one row: the old fixture presented a value that is the real
digest, the policy returned the real digest, and the test called that a security failure.

## 5. The falsification: the assertion still has teeth

The brief's instruction was to stop if the fix made the policy-widened case pass. It does
not — and the half that matters is which assertions catch the widening, so here is that
measured rather than assumed.

**The widened policy** — `alter policy api_keys_cafaye_resolve on api_keys to identity,
identity_app using (true)`, verified by reading `pg_get_expr` back out of `pg_policy`
before the run, not inferred from an exit status:

| test | result against the widened policy |
|---|---|
| **pre-fix** (`7799ead`) | exit **1**, `credential_lookup_test.go:123: tenant A can see 67 api keys, want 1` |
| **post-fix** (`ad24b24`) | exit **1**, `credential_lookup_test.go:126: tenant A can see 65 api keys, want 1` |

Same assertion, same detection capability. **The fix changed nothing about what this test
catches.**

**Which witnesses fire**, measured directly against the widened policy with a fixture row
that exists (baseline first):

| probe | installed policy | widened to `using (true)` |
|---|---|---|
| resolution session, **unqualified** count (case 3, and the case-0 tripwire) | 1 | **64** ← fails |
| **no identity, no digest**, the row's real digest (case 1) | 0 | **1** ← fails |
| a digest **no row has** (the case this packet is about) | 0 | **0** ← does **not** fail |

**So one premise in the brief needs correcting, and it is worth stating plainly because it
is the premise that would have made a weaker fix look like a safe one.** The "a digest no row
has" case is *not* the assertion standing between this property and `using (true)`. Its own
`WHERE token_digest = $1` does that work whether or not the policy is widened, so it returns
0 under a widened policy too. The witnesses are the case-0 tripwire, case 1 and case 3 —
none of which this fix touches.

That does not make the case worthless; it makes it a **fixture-premise** assertion, which is
precisely what it now asserts in the fixture's own voice instead of reporting a correct
policy as a leak. And the fix cannot have removed a widening witness, because it never was
one.

The policy was restored and the restore **verified byte-identical** against the expression
captured before the mutation:

```
(token_digest = ( SELECT cafaye.current_credential_digest() AS current_credential_digest))
```

## 6. The new checks were shown to fire, not assumed to

Every mutation below was applied, **read back out of the file with `grep`/`sed` before the
run** (§8 of the worker contract: an unverified mutation is a recipe that proves nothing),
and reverted with `git checkout --` plus `git diff --exit-code` and a SHA comparison
confirming the tree returned to `ad24b24`.

| # | mutation | result |
|---|---|---|
| A | the case presents `digestFor(tenantA)` — a digest a row **has** | **fires**: `:206 this case presents a digest the fixture seeded a row with…` |
| B | the negative control's sampler cannot detect a collision (`control := "not-the-real-digest"`) | **fires**: `:726 the negative control collided 0 times in 100000, want more than 1000… The sampler has stopped detecting collisions, so the count above is a green that proves nothing.` |
| C | `digestNoRowHas` returns its input — **the defect itself, reintroduced** | **fires**: 3 of 4 table cases plus `:718 digestNoRowHas returned its input for 100000 of 100000` |
| D | the resolve policy widened to `using (true)` | **fires**: the test fails, §5 |

## 7. The sweep for the same shape

Scope derived from content, not from filenames — grepping `*.go` for slice-plus-literal and
literal-plus-slice, then `*.sql`/`*.sh`/`*.yml` for digest mutation, then a second pass on
the *semantic* class ("a value nothing has" asserted against a value derived from a random
one).

- **One other site, in the same file**: `writeInResolution`'s `"0"+digest[1:]` — fixed (§3.3).
- **Zero other sites repo-wide.** Nothing else builds an absent value by mutating a
  `gen_random_uuid()`-derived one.
- **The closest analogue elsewhere** is `internal/oidc/client_test.go:81`,
  `SecretDigest(secret+"x") == digest` — same shape, and **not** this defect: the input is a
  fixed constant rather than a random one, and the comparison goes through SHA-256, so there
  is no rate at which it could flake. Reported for completeness of the sweep only.
- `internal/apikeys/store_test.go` builds its digests as `"cafaye_" + strings.Repeat("k",43) + name`
  — deterministic and distinct by construction. That is already the robust form.

## 8. Gates

| gate | result |
|---|---|
| `bin/prime` **with** the database | **clean** |
| `go vet ./...` | **clean** |
| `go test -race -count=1 ./...` (with DB) | **clean**, 1m40s |
| `gofmt -l .` | **red — pre-existing on master, not mine.** See §9.1 |
| `golangci-lint run ./internal/tenancy/...` | 0 issues |

**Nothing skipped, nothing sharded, no missing toolchain.** Named explicitly:

- Every measurement above ran **against a live database**. I also verified the skip path is
  still honest: with no `TEST_DATABASE_URL` the DB test **skips loudly**, `REQUIRED_DB=1`
  turns that into a **FAIL** (shown, both `credential_lookup_test.go:73` and
  `tenancy_test.go:114`), and `bin/prime` without the database is **red by design** via
  `TestTheDatabaseTierActuallyRan` in `internal/apikeys` and `internal/courier`.
- The new unit test was checked **with and without** a database: it runs and passes either
  way, so it is not a skip that could become a vacuous green on a machine without Postgres.
- **Not run:** `bin/coverage-floor` (needs a coverage profile over the whole suite; not one
  of the four gates and not part of this packet) and `caf contract lint`.

## 9. Findings outside the packet

**9.1 — `gofmt -l .` is red on a clean checkout of master, so one of the four gates is red
for everyone.** `internal/platform/ci/rollback_test.go`, from `25b4441`. Not touched by me
(`git status` shows only my one file). It needs the spaces around `+` in five
multi-line string concatenations plus a trailing newline at EOF:

```sh
gofmt -w internal/platform/ci/rollback_test.go   # the whole fix
```

I did **not** apply it: it is another packet's file and a stray formatting commit is not
mine to spend a review slot on. It is one command and it unblocks a red gate.

**9.2 — `internal/outbox/publisher_test.go:257` is load-flaky, and it is the same class of
defect as this packet's.** `TestServiceReleasesTheBatchWhenTheContextIsCancelled` failed once
during a full-suite run at 167% CPU (`RunOnce = <nil>, want context.Canceled`), and passed
5/5 in isolation, in a second full-suite run, and under `-race`. Mechanism: the test cancels
the context from the test goroutine while `RunOnce` races to finish — if the worker wins
(the main goroutine descheduled between `go func()` and `cancel()`), `RunOnce` returns nil
and commits. The deterministic shape is to have the fake publisher **signal that it has
entered `Publish`**, wait for that signal, and *then* cancel: that creates the
happens-before edge the assertion is really about. I did not fix it — different package,
different owner — but it is a red run in someone's gate and it deserves a packet.

**9.3 — the shared dev database is not empty, and it is a trap when debugging tenancy by
hand.** It carries ~63–65 `api_keys` rows and 332 accounts / 2346 users from other
packages' `dbtest.Schema` fixtures. The credential lookup test itself leaks **nothing** —
measured around a run: accounts 332→332, users 2346→2346, and its own rows are cleaned.
But a naive `select count(*) from api_keys` in that database reads **0**, because FORCE RLS
hides every row from a session with no identity. That is not a fact about emptiness; it is
the boundary working. It caught me: my first widened-policy probe reused a digest whose
fixture I had already deleted, so it measured an absent row instead of the policy and
reported 0 where the truth was 1. I redid the probe with a fixture row present and the
corrected numbers are in §5.

## 10. What I chose not to do, and why

- **I did not touch the policy or the migration.** A genuinely widened policy would fail on
  *every* run; this failed on one in sixteen. §5 shows the policy is narrow and the fixture
  was the liar.
- **I did not make the seed deterministic** (a fixed tenant id, which would make the old
  collision permanent rather than 1-in-16). That trades a flake for a fixture that no longer
  exercises two independent tenants, and every other assertion in this file — distinct keys,
  distinct slugs, a resolution for A that must not return B's row — is built on those ids
  being independent. The helper keeps the randomness and removes the probability, which is
  the only way both properties survive.
- **I did not turn the "no row has" case into an unqualified count** to give it teeth as a
  widening witness. It would duplicate case 3, and §5 shows the widening already has three
  witnesses, none of them mine.
- **I did not fix 9.1 or 9.2.** Both are real and both are outside this packet; the manager
  should decide, and both fixes are written down above so deciding is cheap.
- **I did not add a `DECISIONS.md` entry**, and that is a judgement rather than an omission.
  The trade is real (helper that picks its replacement, versus a deterministic seed, versus
  a hard-coded literal digest), but D1–D10 are all *boundary* rulings on questions this
  repository had to escalate, and the file's own preamble says a settled decision moves to
  the CHANGELOG. A fixture bug is not an open question, so the reasoning went next to the
  code — on `digestNoRowHas`, where the next person to touch it will read it — and here.

## 11. What I would do next

1. **Packet the outbox flake (9.2).** Same class, same fix shape, and it is a red run in a
   gate today.
2. **Sweep the fleet for this defect class rather than this instance**: any test that
   asserts *"no row has X"* where `X` is derived from a `gen_random_uuid()`. My sweep says
   this file was the only site in `identity`; a repo-wide read of every site asserting
   absence against a random-derived value would close it properly.
3. **Consider promoting the idea.** The general lesson is cheap and reusable: a test that
   asserts absence should assert the absence *policy-independently* — against the values the
   fixture wrote — so a collision is a red build that names the fixture rather than a red
   build that names the boundary. `internal/tenancy` now does this in one place; three other
   packages assert absence in the shape I had to fix.

---

## Appendix — every measurement, reproducible

Every command carried a `timeout`; the longest was 700s on the full `-race` suite, which
finished in 1m40s. **The measurement scripts are not committed** — they are one-off
instrumentation, and `bin/` in this repository holds scripts CI and the dev loop reference,
which these are not. Everything each one did is below, so nothing in this report depends on
a file you do not have. `psql` is `postgres://identity:cafaye@localhost:5432/identity?sslmode=disable`.

**§2(b) — the collision rate over the generator**

```sql
select count(*), count(*) filter (where substr(u,28,1) = '0'),
       round(count(*) filter (where substr(u,28,1)='0')::numeric / count(*), 5)
from (select gen_random_uuid()::text as u from generate_series(1,200000)) s;
-- 200000 | 12641 | 0.06321
```

**§4 probes A/B/C — the deterministic demonstration.** Seed one account + user + key under
`cafaye.begin_account('a1b2c3d4-e5f6-4a8b-9c0d-1e203a4b5c6d')` with
`token_digest = 'a1b2c3d4-e5f6-4a8b-9c0d-1e203a4b5c6da1b2c3d4-e5f6-4a8b-9c0d-1e20'`, commit,
then three separate transactions, each rolled back:

```sql
-- A and B present the same string; C presents '0'||that[2:]
begin; select cafaye.begin_credential('<D>');
select count(*) from api_keys where token_digest = '<D>';       -- A: 1,  B: 1
rollback;
begin; select cafaye.begin_credential('0<D[2:]>');
select count(*) from api_keys where token_digest = '0<D[2:]>';   -- C: 0
rollback;
```

**§5 — the widening and its witnesses**

```sh
# capture first, so the restore can be VERIFIED rather than trusted
psql -At -c "select pg_get_expr(polqual, polrelid) from pg_policy
             where polname='api_keys_cafaye_resolve';" > resolve-policy-qual.txt
psql -c "alter policy api_keys_cafaye_resolve on api_keys
          to identity, identity_app using (true);"
psql -At -c "select pg_get_expr(polqual, polrelid) from pg_policy
             where polname='api_keys_cafaye_resolve';"   # must print: api_keys_cafaye_resolve => true
go test -count=1 -run TestTenancyACredentialResolves ./internal/tenancy/
# restore, then diff the deparsed expression against the captured file
```

**§6 — the mutations**, applied with `perl -0pi -e`, each read back with `grep` before the
run and each reverted with `git checkout --` + `git diff --exit-code`:

| # | substitution |
|---|---|
| A | `{"a digest no row has", tenantA, digestNoRowHas(digestFor(tenantA)), 0},` → `{"a digest no row has", tenantA, digestFor(tenantA), 0},` |
| B | `if control := real[:63] + "0"; control == real {` → `if control := "not-the-real-digest"; control == real {` |
| C | the whole body of `digestNoRowHas` → `return real` |

**§4 run logs** — before: 46 `PASS` + 2 `FAIL` (runs 30 and 38), each FAIL naming
`resolve_a_digest_no_row_has` and a digest prefix (`32b0796d…`, `6f57fb2c…`). After: 48
`PASS` + 0 `FAIL`, then a second batch of 48 with 0 `FAIL`.