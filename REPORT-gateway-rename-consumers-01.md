# REPORT — gateway-rename-consumers-01

Point the consumer repositories at `gateway`.

Branch per repo: `worker/gateway-rename-<repo>`. Nothing pushed, nothing merged,
no tags. `guard`, `kit`, `core`, `site` and `pantry` were not touched; `site`
and `pantry` have live workers and I did not open a worktree in either.

## Outcome

| repo | result | commit |
|---|---|---|
| `identity` | **62 references renamed**, gate green at its exact baseline | `85d5db5` |
| `parlor` | **compose contract + e2e tier + the gate that greps it**, gate green at its exact baseline | `99018db` |
| `cafe` | **3 references renamed**, gate green at its exact baseline | `f98fe72` |
| `cafaye-ts` | **untouched, and that is the correct answer** — proven below | — |
| `courier` | untouched, 4 sites enumerated in a handoff | — |
| `docs` | untouched, ~110 sites scoped in a handoff | — |

Two of the six are committed changes, one is a proven no-op, and two are
hand-offs with the sweep already scoped. `docs` and `courier` were left alone
deliberately and each has a `HANDOFF-gateway-rename-consumers-01.md` committed
on its branch.

## The trap, and how the two senses were separated

`guard` means two things in this fleet: the service, and *a tripwire* — the
thing that asserts something, used the way "test" or "lint" is used. The
majority of every repository's occurrences are the second sense. Renaming those
produces documents that are actively wrong, and these are the documents work
gets dispatched from.

I did not sweep on a filename pattern or on the high-confidence token shapes
alone. For each repository I read the sentence at every site and classified it.
Where I could make a decision mechanical I did — but only inside files I had
first read end to end and confirmed were single-sense, and the script printed a
MISMATCH and applied nothing for every literal that did not occur exactly once,
so a stale copy of a string is a loud failure rather than a quiet half-sweep.

### Counts, per repo

| repo | word | renamed | tripwire, left | deliberate exceptions |
|---|---|---|---|---|
| `identity` | 91 | 62 | 27 | 2 (`guard-02` packet id ×2) |
| `parlor` | ~180 (excl. logs) | ~90 | ~85 | `../guard` paths, `path: guard` |
| `cafe` | 22 | 3 | 19 | — |
| `cafaye-ts` | 27 | **0** | 20 | 7 vendored/generated, proven |
| `courier` | 193 | 0 (handed off) | ~189 | 4 service, hand-written up |
| `docs` | ~207 | 0 (handed off) | ~40 | ~110 service, some blocked |

## Judgment calls a reader might have made differently

**1. `cafaye-ts` was not swept at all. This is the finding I would most want
reviewed.** Its 27 occurrences divide into 20 tripwires and 7 that name the
service — and every one of the 7 is inside a file pinned by a commit sha and a
recorded digest:

- `specs/identity.yaml` (3), `specs/muse.yaml` (2), `specs/pantry.yaml` (1) —
  vendored copies read at a recorded commit by `scripts/vendor.mjs`, which uses
  `git cat-file -p <commit>:<path>` and never the working tree.
- `src/services/identity/sdk.gen.ts` (2), `src/services/identity/types.gen.ts`
  (1) — generated from those vendored documents.

`specs/index.json` records `identity` at commit `793977be…` with
`sha256 9effe3aa…` and `bytes 176958`. Editing one word in the vendored YAML
changes its digest and its byte count, which `test/vendored-specs.test.mjs`
asserts. It also falsifies the provenance claim: the file is a byte copy of
identity *at that commit*, where the text said `guard`.

I did not assert this. I applied the edit and ran the gate:

```
before: npm run verify:specs  -> exit 0
        "specs/index.json and the 6 vendored documents agree. 72 operations across the fleet."

after:  (sed -i '' 's/requires `scopes`, and guard's/…gateway's/' specs/identity.yaml)
        verified in the file: specs/identity.yaml:2424 now reads "and gateway's"
        npm run verify:specs  -> exit 1

        - identity (specs/identity.yaml): contents do not match the index.
          index: 9effe3aa5c080489b35fab04d7fd42f0ce7cf4b4f4942a92ca4dadfe9766b5cf
          file:  ee4eeab57d28bbb2fcd2952a699928121de33471e060a04bde0ee3b3842919ee
          The vendored document was edited by hand, or it was vendored from a
          different commit. Never edit it — run `npm run vendor`.
```

Reverted, and `verify:specs` is green again at exit 0. Note what the checker's
own note in `specs/index.json` already says: *"this vendored copy goes stale
the moment that lands. That is expected and is not a failure of this
repository."* The vendored identity document is a declared-stale historical
snapshot. **Re-vendoring is `npm run vendor -- --service identity --bump`, a
deliberate human act that moves the pin to a commit that exists.** It is not
this packet's to do, and it must not be done as a side effect of a rename.

**2. `parlor`: I renamed the compose service name and deliberately did not
rename `../guard`.** The compose service `guard` is now `gateway`, along with
`guard-redis`, `guard-redis-data`, `REDIS_URL: redis://gateway-redis:6379`,
`SIBLING_SERVICES`, `READY_SERVICES`, the `cafaye/gateway:e2e` tag,
`E2E_GATEWAY_PORT`, `E2E_GATEWAY_REDIS_PORT` and `guardBaseUrl`. What stayed is
every **filesystem path** to the sibling checkout: `context: ../guard`,
`path: guard`, and `../guard/Dockerfile`. Renaming those points the build at a
directory that does not exist on this machine, because the repository rename is
the manager's and has not happened. A comment reading `built from ../guard`
stays true on the day the directory is renamed.

**3. `parlor`: the gate that greps the renamed name is part of the sweep.**
`tests/validate-ci.sh:1429` holds a self-test case whose entire mechanism is a
mutation: `sed -i '' 's|E2E_GUARD_REDIS_PORT:-16002|E2E_GATEWAY_REDIS_PORT:-6379|'`.
Renaming the variable in the compose file without renaming it here makes that
`sed` a no-op, the check stays green, and the self-test case fails. Proven by
count rather than by argument:

```
grep -c 'E2E_GUARD_REDIS_PORT:-16002' e2e/docker-compose.yml   ->  0
grep -n  'E2E_GATEWAY_REDIS_PORT:-16002' e2e/docker-compose.yml ->  320
```

**4. `identity`: one applied migration was left alone, for a mechanical reason.**
`migrations/00016_account_isolation.sql:198` still says "guard verifies JWKS
bearer JWTs". `migrations/README.md:41-43` states that the goose table records a
checksum and that *"changing a file that has already run somewhere makes goose
refuse to apply anything after it."* A comment edit is not a schema change but
it is not mechanically distinguishable from one to the tool reading the
checksum, and AGENTS.md's "never edit an applied migration" is absolute. The
cost of overriding it is a service that will not deploy.
(`migrations/00010_mfa.sql:192` is "the replay guard" — tripwire, other reason.)

**5. `docs` was left whole, and the reason is ordering rather than size.** It is
the largest surface (~110 service sites), but the decisive point is that its
riskiest edits are blocked on the gateway-repository packet running in
parallel. `GUARD_CLIENT_ID`, the `guard:rl` `REDIS_PREFIX` default, the
`guard-api`/`guard-auth` rate-limit bucket names, `CREATE DATABASE guard`, the
`8080:guard` runbook loop and the `grep -c guard` diagnostic are all names the
**gateway service itself** owns. Renaming them in the docs before that packet
merges produces a runbook that tells an operator to look for a container that
does not exist. `docs` also has no `redirects:` block in `astro.config.mjs`, so
renaming `services/guard.md` breaks every published `/services/guard/` URL, and
that URL is outward-facing. Both decisions are written up in the docs handoff
with the ~70 sites that *are* safe to sweep now.

**6. `identity`: comment wrapping was left alone.** `gateway` is four characters
longer, so 25 lines grew by that much. These files already carry 84-to-237-column
lines, so there is no wrap to keep and rewrapping would have been a reformat of
nothing.

## What was deliberately not changed

- **The GitHub repository name.** The manager's, and outward-facing.
- **`guard-02`** in `cafaye.yml:243` and `internal/apikeys/claims.go:35` — a past
  dispatch's packet id. A report saying a packet named `guard-02` decided
  something is a true record of what it was called.
- **`CHANGELOG.md` service prose** in identity was renamed (7 sites, it describes
  a live cross-service contract); **`REPORT-*.md`, `HANDOFF-*.md`, `logs/`** were
  not, in any repository. They are the record of what past dispatches did.
- **`docs/src/content/docs/services/guard.md`** — not renamed; see judgment 5.
- **`site` and `pantry`** — live workers, not opened.

## Measurements

Every gate was run before and after on the same machine. `identity` and `cafe`
against a real migrated PostgreSQL; `parlor` including its own
`validate-ci.sh` self-test.

**`identity`** — `go test -v -count=1 ./...`, counted with ci.yml's own awk
shape (per-package `--- PASS:` lines):

```
before: 2399 PASS, 3 SKIP, 0 FAIL, exit 0
after:  2399 PASS, 3 SKIP, 0 FAIL, exit 0
per-package diff: IDENTICAL
```

The 3 SKIPs are the declared `E2E_SKIP_EXCEPTIONS` in `internal/courier`. Above
`SUITE_FLOOR: 2299`. `gofmt -l .` and `go vet` on the touched packages are clean.

**`parlor`** — `./bin/prime`:

```
                    before              after
Test Files           31 passed (31)      31 passed (31)
Tests                727 passed (727)    727 passed (727)
validate-ci.sh       46/0/0              46/0/0
self-test cases      53 ok               53 ok
exit                 0                   0
```

Plus `shellcheck -S warning` clean on all five changed shell files, `bash -n`
clean on all five, `tsc --noEmit` clean.

**`cafe`** — `./bin/prime`, baseline obtained by `git stash` so it is a real
before, not a remembered one:

```
before (stashed to master): 15 packages, 727 top-level, 876 subtest, 0 failures, 8 skips, exit 0
after:                      15 packages, 727 top-level, 876 subtest, 0 failures, 8 skips, exit 0
```

cafe's gate prints its own countable row for the skips: `live tier: 0 of 7
executed; not enabled, so the 7 live tests skipped rather than ran`, gated behind
`CAF_LIVE_DOCKER=1`, `CAF_LIVE_RYUK=1`, `CAF_LIVE_KAMAL=1`. They did not run and
are not claimed to have. That is 7 of the 8 skips; the eighth is not live-tier.

**`identity` regenerated, not hand-edited.** `go generate ./client/` moved 17
comment lines and nothing else — verified by reading every changed line in
`client/generated/api.gen.go`, all of them inside `//`. A hand-edit would have
satisfied the prose and failed
`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces`.

## One error I made and caught

`identity` first came back **red**: 2398 PASS instead of 2399, with
`TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` failing on "the
generated file is staged with changes against the last commit". That was my own
harness error — I started the suite in the background and then ran `git add -A`
and `git commit` while it was still running, so the test read a dirty tree. The
number above is from a re-run on the clean committed tree.

The real parlor equivalent is worth more: my token sweep renamed `E2E_GUARD_PORT`
in `bin/e2e` but left its `host-port guard` argument, so the script would have
asked `e2e-stack` for the published port of a compose service that no longer
existed. Declarations are easy to sweep; call sites are where a rename hides.

## Findings outside the packet

1. **`identity/internal/platform/ci/rollback_test.go` is gofmt-dirty on master.**
   `gofmt -l .` names it on a clean checkout of `master` and the file is
   byte-identical between master and this branch, so it predates this packet.
   AGENTS.md lists `gofmt -l .` as one of the four gates that must pass before a
   commit lands, so identity's stated gate is currently red for a reason
   unrelated to this work. Not fixed here — out of scope, and it is a
   formatting change to a file a reader would want to see on its own.

2. **The packet brief says "identity and courier are Go". Courier is Elixir**
   (`mix.exs`, `lib/courier/**/*.ex`). It has genuinely different gates — ExUnit
   prints a countable `N tests, M exclusions`, where Go prints none — so it was
   swept with a different method rather than the same one.

3. **`cafaye-ts`'s vendored identity document is stale and says so.**
   `specs/index.json` declares it stale against identity-08 and pins it at
   `793977be…`. It is now staler, because this rename changed identity's
   `openapi/v1.yaml`. Whoever re-vendors should expect three more `gateway`
   sites to resolve themselves at that point rather than being edited.

4. **`parlor`'s `host-port <service>` has no existence check.** It reads a
   compose service name as a string; a name that matches nothing is not an error
   at the point of use. That is what let my own slip through to the commit diff.
   A check that the service exists in the compose document would have caught it
   at `bin/e2e` instead.

## What I would do next

1. `courier` — four substitutions in two files, one `mix test` before and after,
   the whole thing enumerated in its handoff. Cheapest remaining item.
2. `docs` — after the gateway-repository packet merges. The handoff lists the
   ~70 unblocked sites, the six that must wait, and the `/services/guard/`
   slug decision with the `redirects:` consequence.
3. Re-run this sweep's grep across `site` and `pantry` once their workers land;
   the manager has those queued.

## Housekeeping

- Every command was run under a bounded `timeout`.
- No container, image or volume was created or left running. No `docker prune`.
  identity's suite ran against the **pre-existing** native PostgreSQL 18 on
  127.0.0.1:5432 that the `identity` role and database were already provisioned
  in; nothing about it was changed.
- Other sessions' worktrees (`wt-parlor-gatefix-01`, `wt-tanstack-parlor-01`,
  `wt-tanstack-site-01`, `wt-m39-pantry-*`) were left alone.
- `cafaye-ts`'s untracked `REPORT-revendor.md` is not mine and was not touched.