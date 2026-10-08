# REPORT-local-gate-m117 — identity local gate evidence (verification-only)

Packet m117. Verification only: no product code changed, no rerun, no patch.
Branch `worker/m117-local-identity-gate`; this report is the only committed file; not pushed.

## Revision

- Worktree: `/Users/kaka/Code/any/wt/identity`
  (same directory as session cwd `/Users/kaka/Code/any/moon/cafaye/identity`
  via symlink; `wt` resolves to `moon/cafaye`).
- HEAD: `b5f756a` — "identity: redeem invitations under RLS via a
  digest-scoped policy (m112)".
- Tree was clean before the run (`git status --short` empty) and is clean
  apart from this report after it. `go mod download` / build cache only;
  no source file touched.

## Gate read before running

- `AGENTS.md` (gates section: `bin/prime`, `go vet ./...`, `gofmt -l .`,
  `go test -race ./...`; DB tier fails red without Postgres; DSN guidance).
- `bin/prime` (exact declared gate: `go mod download`, `go build ./...`,
  self-provision via `bin/provision-testdb` when `TEST_DATABASE_URL` is set,
  then `go test -count=1 -p 4 ./...`).
- `gate.yml` (declared command `[bin/prime]`; proofs are per-package `ok`
  lines; Go prints no test count so there is no `minimum` floor).

## Command (run exactly once)

```
TEST_DATABASE_URL='postgres://identity@127.0.0.1:15527/identity_gate_m117?sslmode=disable'
TEST_DATABASE_ADMIN_URL='postgres://postgres@127.0.0.1:15527/postgres?sslmode=disable'
timeout 1800 ./bin/prime
```

Passwords omitted everywhere in this report by rule; both are local-only
test credentials, no production secret involved. The exact argv was
`timeout 1800 ./bin/prime`, launched once in the background with stdout+stderr
to the log below. It was not rerun after the failure.

## Log and exit evidence

- Full log: `/tmp/gate-m117-identity-local.log` (301 lines).
- Run start: epoch recorded in `/tmp/gate-m117-identity-local.start`.
- Elapsed: 92 s wall (start file to last log write; well inside the 1800 s bound).
- Exit: NONZERO — the log ends with a top-level `FAIL` and exactly one
  `--- FAIL` line. Launcher gap, stated honestly: the background launcher did
  not write a `.exit` file, so the precise numeric code was not captured;
  the captured fact is `FAIL`/nonzero (the `go test` failure path).
  The log itself is complete from `provision-testdb` line 1 to the final `FAIL`.

## Database used / dropped

- Used: database `identity_gate_m117` on the standalone local Postgres
  container `identity-w27-pg` (`localhost:15527`), created fresh by the gate's
  own `bin/provision-testdb` (owner role `identity`, app role `identity_app`,
  all 29 migrations `00001`–`00029` applied, `GRANT identity_app TO identity`).
- Not dropped: left in place, matching prior workers' `identity_gate_*`
  databases on the same container.
- Untouched: the `site-launch-*` stack (active on host port 15500 and siblings)
  was not installed/launched/stopped/modified; no publish/deploy command run;
  no other database on the container (`identity`, `identity_gate_w*`,
  `identity_w104_rlsbydigest`, …) was read or written. Verified read-only that
  the pre-existing `identity`/`identity_app` roles authenticate before use.

## Result: FAIL — one failing test, everything else green

- `--- FAIL` lines: 1. `--- SKIP` lines: 0 (non-verbose log carries no
  per-test lines; a skip count is only measurable from CI's `-v` run).
- Package lines: 27 `ok`, 3 `[no test files]`
  (`client/generated`, `internal/platform/dbtest`, `internal/ratelimit`),
  1 package `FAIL` (`internal/platform/ci`), plus the top-level `FAIL`.
- All gate.yml proof packages print `ok`: `client`, `cmd/identity`,
  `internal/mfa`, `internal/apikeys`, `internal/admin`, `internal/httpapi`,
  `internal/auth`, `internal/config`. EXCEPT the `ci-guard-ran` proof:
  `internal/platform/ci` as a package is red, so that proof does not hold
  in this run.

## Exact failure summary

Single failure: `TestTheNamedSecurityTestsExist`
(`internal/platform/ci/ci_test.go:518`), 77 errors, all of the form:

```
ci_test.go:527: ci.yml names <TestName> as a test that must run, and no such
function exists in this tree.
```

Static verification against the same tree (read-only `grep`, no execution,
no code change): every name the workflow lists exists as a test function.
Parsing the security-test list out of `.github/workflows/ci.yml` yields 80
names; 0 of them are missing as `func <Name>(` in `*_test.go`. Spot checks on
names from the failure output:

- `TestAResetTokenIsNotAVerificationToken` —
  `internal/recovery/password_reset_test.go:460` (and named at `ci.yml:769`).
- `TestAChangeClearsTheVerificationAndEndsEveryCredential` —
  `internal/recovery/email_change_test.go:202`.
- `TestADatabaseDumpYieldsNoWorkingSecondFactor` —
  `internal/mfa/store_test.go:699`.

So the check's claim ("no such function exists in this tree") is factually
wrong for the sampled names, and the miss rate is 77/77, i.e. the tree walk
(`testNamesInTree`, `ci_test.go:767`, via `repoRoot` at `ci_test.go:796`)
returned effectively empty during this run rather than finding a genuinely
absent test. The failure is in the guard's own directory walk, not in missing
security coverage and not in product code. Root cause of the empty walk is
not established (single definitions confirmed, tree clean, no second copy of
the helpers); recorded here as a finding for the owning packet, not a fix —
this packet is verification-only.

## What did not run (by design of this packet)

`go vet ./...`, `gofmt -l .`, `go test -race ./...`, and `bin/coverage-floor`
were not run: the brief declares `./bin/prime` once as the whole packet.
Coverage/test-count totals are not measurable from this non-verbose log
(Go prints per-package durations only); the decrease-detector floors live in
`.github/workflows/ci.yml` (`SUITE_FLOOR`, `DATABASE_TIER_FLOOR`).

## Handoff

- Successor's first move: reproduce/diagnose why `testNamesInTree`'s
  `filepath.WalkDir` sees no `*_test.go` files under `bin/prime` (works
  statically, fails in-gate) — e.g. a focused `-run` of
  `TestTheNamedSecurityTestsExist` with walk diagnostics, owned by a packet
  that is allowed to touch `internal/platform/ci`.
- Evidence: this file (committed), `/tmp/gate-m117-identity-local.log`,
  `/tmp/gate-m117-identity-local.start`, database `identity_gate_m117` on
  `localhost:15527` (tells the same story on re-inspection; migrations at v29).
