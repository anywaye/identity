# REPORT m151 — Fix fresh Identity gate database provisioning

Branch: `m147-identity-system-admin` (continues; m147/m147b already at `98b7831`, untouched).
Scope: `bin/provision-testdb` + one new test file. Nothing else.

## Measured failure (from the brief)

Merged `./bin/prime` against a clean local Postgres 17 on `127.0.0.1:15527` failed in
`bin/provision-testdb` creating `identity_app`:

```
ERROR: syntax error at or near ":"
LINE 1: CREATE ROLE identity_app LOGIN PASSWORD :'pw'
```

## Root cause

`bin/provision-testdb` passed `:'pw'` through `psql -c`. psql performs
`:'var'` interpolation on the input it scans (interactive, `-f`, stdin) and
sends `-c` straight to the server, so the server received a literal `:'pw'`
and rejected it. The password-as-variable promise was correct; the channel was
wrong.

## Fix

Both role creations (owner, `<owner>_app`) now feed the statement on stdin:

```sh
printf '%s\n' "CREATE ROLE $owner LOGIN PASSWORD :'pw'" | \
  "$psql_bin" "$admin_dsn" -X -q -w --set ON_ERROR_STOP=1 -v pw="$password"
```

Preserved: safe-identifier validation (names stay shell-interpolated),
`-v pw="$password"` binding, no raw password in SQL or logs, idempotency,
local-host refusal, admin-DSN order. Header comment updated to state the
stdin-not-`-c` rule and why.

## Tests

New `internal/platform/ci/provision_testdb_test.go`, three tests:

- `TestProvisionTestDBRoleCreationUsesAStdinVariable` — static hold on the
  script: no `-c "CREATE ROLE`, exactly 2 `PASSWORD :'pw'` literals, exactly
  2 `-v pw="$password"` bindings, printf pipe present, raw password nowhere
  outside the binding.
- `TestProvisionTestDBOldFormIsRejectedAndTheNewFormDeliversAVariable` —
  executes both call shapes against a fake psql modelling the real contract
  (`-c` bypasses interpolation, stdin does not): old shape exits nonzero
  with the server's `syntax error at or near` rejection; new shape (quoted
  exactly as the script writes it, with a hostile `s3cret' OR '1'='1`
  password) delivers `PASSWORD :'pw'` with the secret nowhere in the SQL.
- `TestProvisionTestDBIsValidBash` — `bash -n` on the script.

## Verification

- `bash -n bin/provision-testdb` → clean.
- `go test ./internal/platform/ci/ -run 'TestProvisionTestDB' -count=1` → 3/3 PASS.
- `go test ./internal/platform/ci/ -count=1` (whole package) → ok.
- `gofmt -l internal/platform/ci/` → clean. `go vet` → clean.
- Tripwire shown to bite: with the fix stashed (old `-c` script restored),
  `TestProvisionTestDBRoleCreationUsesAStdinVariable` FAILs; fix restored.
- NOT run per the brief: `./bin/prime`, full suite, Docker, manager's live DB.
  Fresh-Postgres merged gate rerun belongs to the manager.

## Handoff

Manager: merge this, rerun the fresh-database full gate, push, then remove the
exact task DB/container/volume. No open threads in m151.
