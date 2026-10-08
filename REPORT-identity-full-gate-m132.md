# REPORT — identity full gate m132 (existing-behavior release-readiness)

## HEAD / tree

- Worktree: `identity-m127-postreset-mfa`
  (`/Users/kaka/Code/any/moon/wt/identity-m127-postreset-mfa`)
- Worktree HEAD: `7ca0865301ec5fe6000f01bfa07ac242b5aace7c`
- Reference HEAD (`/Users/kaka/Code/any/moon/cafaye/identity`, master):
  `7ca0865301ec5fe6000f01bfa07ac242b5aace7c`
- HEAD match: YES (equal). Worktree tree was clean before and after the run
  (`git status --short` empty apart from this report file); no product or test
  source was changed, no gates loosened.
- Note: the reference checkout's local master is ahead of its `origin/master`
  (`b5f756a8a1437d05879e7406a4cde32d9cabdf55`) by 9 unpushed commits. This run
  gates the local-master tip `7ca0865`, i.e. exactly the tree in this worktree.
- No uncommitted partial work from a prior attempt was present
  (`git status --short` was empty at dispatch).

## Command (run exactly once, bounded, worktree-keyed log)

```
TEST_DATABASE_URL=postgres://identity@127.0.0.1:15527/identity_gate_m132?sslmode=disable ./bin/prime
```

- Database `identity_gate_m132` is unique to this packet/worker; no other
  worker's database was shared, used, or deleted. Provisioning was done by the
  gate itself (`bin/provision-testdb`: created database, applied migrations).
  (Credential omitted from this report; host/port/database only.)
- Gate log: `gate-identity-m127-postreset-mfa-m132.log` (67 lines),
  with `.start` / `.exit` / `.end` sidecar files in the shared temp dir.
- The gate was NOT rerun (single run, exit 0, no transient harness issue).

## Gate result: PASS (exit 0)

- `go mod download`: ok (no errors in log)
- `go build ./...`: ok (no errors in log)
- `go test -count=1 -p 4 ./...`: **28 packages `ok`, 0 `FAIL`, 0 panics**
- `--- SKIP:` lines: none. `--- FAIL:` lines: none.
- Packages with no test files (3, expected): `client/generated`,
  `internal/platform/dbtest`, `internal/ratelimit`.
- Per-test counts are not printed by `bin/prime` (known property, see
  `gate.yml`), so package lines are the count: 28 ok / 31 total entries.

## Durations

- Wall clock: 2026-10-08T02:27:23Z → 2026-10-08T02:29:16Z = **113 s**
  (shell total 1:53.40: 55.57 s user, 15.02 s system, 62% cpu).
- Slowest packages: `internal/httpapi` 81.1 s, `internal/accounts` 35.9 s,
  `internal/mfa` 31.7 s, `internal/apikeys` 31.4 s, `internal/auth` 24.2 s,
  `internal/recovery` 21.9 s, `internal/outbox` 19.2 s,
  `cmd/identity` 16.8 s. All remaining packages under 10 s each.

## Failures

None. No diagnostics beyond the passing gate outcome were needed; per the
brief no further commands were run.

## Toolchain

- `go version go1.26.1 darwin/arm64`
