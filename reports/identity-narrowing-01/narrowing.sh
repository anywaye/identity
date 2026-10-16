#!/usr/bin/env bash
#
# reports/identity-narrowing-01/narrowing.sh — can identity's tenancy suite be
# made to fail by making a policy TOO STRICT, so a LEGITIMATE principal is
# refused?
#
# WHY THIS EXISTS. moon/DEBT.md's D18 records that the fleet's isolation suites
# have only ever been shown to catch breakages that WIDEN a boundary. pantry got
# the opposite proof first (reports/pantry-narrowing-01/narrowing.sh), and this
# is identity's, built to that contract and against THIS repository's shape.
#
# THE SHAPE IS DIFFERENT FROM pantry's AND THE DIFFERENCE IS LOAD-BEARING.
# pantry's `tests/rls.sh` stands a scratch cluster up from `migrations/` on
# every run, so editing a migration changes what the suite tests. identity's
# suite runs against a database that an EXTERNAL provisioner built once
# (`bin/provision-testdb` + goose), so editing a migration file changes NOTHING
# until the migrations are applied again. A mutation recipe that edited files
# and re-ran the suite here would print a green and mean nothing. So this recipe
# OWNS the provisioning: for every mutation it drops and re-creates one
# uniquely-named disposable database on the shared cluster, applies the MUTATED
# migrations with goose, runs the suite against it, and queries that same
# database for the witness. One mechanism, the same one the gate uses.
#
#   bash reports/identity-narrowing-01/narrowing.sh              # control + part 1
#   bash reports/identity-narrowing-01/narrowing.sh --phase control
#   bash reports/identity-narrowing-01/narrowing.sh --phase part1
#   bash reports/identity-narrowing-01/narrowing.sh --list
#   bash reports/identity-narrowing-01/narrowing.sh --keep-db    # do not drop the scratch db
#
# ---------------------------------------------------------------------------
# WHAT A RED HAS TO BE, OR THE RESULT IS NOT THE POINT
# ---------------------------------------------------------------------------
# Every mutation below must go red on a check that asserts a LEGITIMATE
# OPERATION WORKS — a rowset that must be non-empty, an own-row count that must
# be 1, an `INSERT 0 1`, a membership list that must contain the caller's own
# account. It must NOT go red only on a check that asserts a refusal: a check
# that wants a refusal cannot be falsified by refusing more.
#
#   RED-LEGITIMATE      at least one red on a check asserting a legitimate
#                       operation works. This is the owed condition.
#   RED-INDIRECT        every red is refusal-shaped, but at least one of them
#                       could not have passed unless a legitimate operation took
#                       effect — the over-refusal was caught downstream rather
#                       than asserted directly. Weaker than RED-LEGITIMATE, and
#                       counted separately; `classify` carries the one rule and
#                       the measurement behind it.
#   RED-WRONG-POLARITY  every red is on a refusal-shaped check that refusing
#                       more cannot falsify. Nothing proved by them.
#   NOT-RED             nothing noticed. Also a result, and printed loudly.
#
# THE POLARITY IS READ OFF WHAT THE SUITE RECORDED, never off the check's name
# and never off the mutation's intent: kit's assertions record `expected` /
# `actual` (an `expected "0"` is a denial; an `expected "2"` is a legitimate
# read), and the Go tests' failures say what they wanted (`want 0` is a denial;
# `want 1` / `want exactly [...]` is a legitimate operation). The one rule that
# is NOT purely mechanical is marked in `classify` with the measurement that
# justifies it.
#
# ---------------------------------------------------------------------------
# WHERE THE MUTATIONS GO, AND WHY THESE PLACES
# ---------------------------------------------------------------------------
# identity's five real tables are protected through `cafaye.protect_table` and
# its two siblings, installed by 00016 and copied from kit's substrate. The
# function BODIES are what write the policies, so narrowing a body narrows the
# policies of every table that call writes — which is exactly what the suite is
# supposed to catch. Three consequences the mutations depend on, all measured:
#
#   * `protect_table` DROPs and re-CREATEs its four policies on every call, so
#     the LAST call wins. Planting a narrowing in the body hits every table the
#     body protects, including the ones a later migration re-protects (00018
#     re-protects account_users, 00029 re-protects account_invitations) — the
#     later call runs the same mutated body, so nothing here is a no-op of the
#     pantry-N4 kind. The one place a no-op COULD live is a narrow of a policy
#     that a later migration drops and recreates with its own literal DDL, and
#     the only such policy in this tree is account_users_cafaye_resolve (00028);
#     no mutation below touches it.
#   * The kit assertion set protects its OWN temp fixture through the same
#     function, so a body narrowing reds BOTH kit's `login/...`/`owner/...`
#     assertions and identity's tests on the real tables. Two instruments, one
#     plant.
#   * `force` is NOT touched. Removing force WIDENS, which is the opposite
#     direction; this recipe is one-directional for the reason pantry's comment
#     gives — a table with both directions needs a "which way" column, and that
#     column is where a mutation recipe starts reporting its own intent back to
#     itself.
#
# ---------------------------------------------------------------------------
# THE WITNESS
# ---------------------------------------------------------------------------
# "Every check passed" is also what a mutation that changed nothing at runtime
# prints, so every mutation is witnessed against the SAME disposable database
# the suite just ran against (mutated migrations applied by goose — no second
# mechanism, no `alter policy` typed by hand). The witness seeds one account, a
# second user, one api_key, one invitation and one audit row, then asks the
# database, as `identity_app`, the seven questions the suite's checks are built
# on: read your own audit rows; discover your memberships by caller; resolve
# your credential; run the ByDigest join; resolve an invitation; UPDATE your
# own membership; INSERT and DELETE your own membership. The BASELINE, printed
# before any plant, is what makes the per-mutation output a diff rather than an
# assertion. Each mutation also prints the LIVE policy out of `pg_policies`,
# because that is what proves the mutation reached the database at all.
#
# ---------------------------------------------------------------------------
# CREDENTIALS
# ---------------------------------------------------------------------------
# THIS SCRIPT NEVER PRINTS A CREDENTIAL. The owner/admin DSNs are assembled in
# the shell from environment variables and passed to psql/goose/go test; no
# command line, log line or report line carries a password. `leak_guard` greps
# every log this script writes for the password and aborts the run if one was
# ever captured. Providing the DSNs directly is also supported:
#
#   IDENTITY_NARROW_OWNER_URL   DSN for the owner role (default: identity@127.0.0.1:15500)
#   IDENTITY_NARROW_ADMIN_URL   DSN for a role that may CREATE/DROP databases (default: cafaye@127.0.0.1:15500)
#   KIT_POSTGRES_PASSWORD       the password for both, when the URLs are not given
#
# The scratch database is named identity_narrow_<8 hex>, is dropped before use
# (with force) and after the run, and nothing else on the cluster is touched.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)" || exit 2
cd "$REPO" || exit 2

SUITE_PKGS="./internal/tenancy/ ./internal/accounts/ ./internal/deletion/ ./internal/recovery/"
SUBJECT_DIRS=(migrations)
INSTRUMENT_DIRS=(internal/tenancy internal/accounts internal/deletion internal/recovery)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/identity-narrowing.XXXXXX")"
SUMMARY="$WORK/summary.tsv"
: >"$SUMMARY"

PHASE="all"
KEEP_DB=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --phase) PHASE="${2:-}"; shift 2 ;;
    --phase=*) PHASE="${1#--phase=}"; shift ;;
    --list) PHASE="list"; shift ;;
    --keep-db) KEEP_DB=1; shift ;;
    *) echo "narrowing.sh: unknown argument '$1'. --phase control|part1|all | --list | --keep-db" >&2; exit 2 ;;
  esac
done
case "$PHASE" in control|part1|all|list) ;; *) echo "narrowing.sh: bad --phase '$PHASE'" >&2; exit 2 ;; esac

CONTROLS_RUN=0; CONTROLS_GREEN=0
PLANTED=0; PLANT_FAILED=0
RED_LEGIT=0; RED_INDIRECT=0; RED_WRONG_POLARITY=0; NOT_RED_LEGIT=0
RESTORED=0; RESTORE_FAILED=0
PROBLEMS=0
LEAKS=0

say()   { printf '%s\n' "$*"; }
rule()  { say "----------------------------------------------------------------"; }
head2() { say ""; say "== $*"; }

# ---------------------------------------------------------------------------
# THE ENVIRONMENT — assembled, never printed.
# ---------------------------------------------------------------------------
# `--list` prints the plan and touches nothing, so it is exempt from the
# credential requirement: a reader checking what this file does should not have
# to hold a password to find out.
: "${KIT_POSTGRES_PASSWORD:=}"
OWNER_URL="${IDENTITY_NARROW_OWNER_URL:-}"
ADMIN_URL="${IDENTITY_NARROW_ADMIN_URL:-}"
if [ "$PHASE" != "list" ] && { [ -z "$OWNER_URL" ] || [ -z "$ADMIN_URL" ]; }; then
  if [ -z "$KIT_POSTGRES_PASSWORD" ]; then
    say "ABORT  no database credentials. Set KIT_POSTGRES_PASSWORD (shared cluster at"
    say "       127.0.0.1:15500, owner identity_role 'identity', admin role 'cafaye'), or set"
    say "       IDENTITY_NARROW_OWNER_URL and IDENTITY_NARROW_ADMIN_URL. No value is ever printed."
    exit 2
  fi
fi
DBNAME="identity_narrow_$(openssl rand -hex 4)"
[ -n "$OWNER_URL" ] || OWNER_URL="postgres://identity:${KIT_POSTGRES_PASSWORD}@127.0.0.1:15500/${DBNAME}?sslmode=disable"
[ -n "$ADMIN_URL" ] || ADMIN_URL="postgres://cafaye:${KIT_POSTGRES_PASSWORD}@127.0.0.1:15500/postgres?sslmode=disable"

# The test URL must point at the scratch database and keep the owner role the
# suite's hard-coded `set role identity_app` needs (tenancy_test.go:298).
TEST_URL="postgres://identity:${KIT_POSTGRES_PASSWORD}@127.0.0.1:15500/${DBNAME}?sslmode=disable"
if [ -n "${IDENTITY_NARROW_OWNER_URL:-}" ]; then
  # A caller-supplied owner URL names its own database; the scratch name is
  # only used for the default construction.
  TEST_URL="$IDENTITY_NARROW_OWNER_URL"
fi

# leak_guard — the run aborts rather than ever carrying a credential into a log.
#
# IT LOOKS FOR THE DSN'S USERINFO FORM (`:password@`), NOT FOR THE PASSWORD
# STRING ALONE, and that is a measurement rather than a preference: this
# cluster's password is the five-letter word that is also the organisation in
# the module path `github.com/cafaye/identity`, so the first version of this
# guard reported a leak on every `go test -json` line that named the package.
# A guard that fires on the repository's own name is a guard nobody keeps.
leak_guard() {
  local f
  for f in "$@"; do
    [ -f "$f" ] || continue
    if [ -n "$KIT_POSTGRES_PASSWORD" ] && grep -qF -- ":${KIT_POSTGRES_PASSWORD}@" "$f" 2>/dev/null; then
      LEAKS=$((LEAKS+1)); PROBLEMS=$((PROBLEMS+1))
      say "ABORT  a log file captured a connection URL's credential (file not printed). This run is not a result."
    fi
  done
}

PSQL_BIN=""
for c in "${IDENTITY_NARROW_PSQL_BIN:-}" /opt/homebrew/opt/postgresql@18/bin \
         /opt/homebrew/opt/postgresql@17/bin /usr/local/opt/postgresql@18/bin \
         /usr/lib/postgresql/18/bin /usr/lib/postgresql/17/bin; do
  [ -n "$c" ] && [ -x "$c/psql" ] && { PSQL_BIN="$c/psql"; break; }
done
[ -n "$PSQL_BIN" ] || PSQL_BIN="$(command -v psql 2>/dev/null)"
[ -n "$PSQL_BIN" ] || { say "ABORT  psql not found."; exit 2; }

GOOSE_BIN="$(command -v goose 2>/dev/null || true)"
[ -n "$GOOSE_BIN" ] || GOOSE_BIN="$(go env GOPATH 2>/dev/null)/bin/goose"
[ -x "$GOOSE_BIN" ] || { say "ABORT  goose not found. Install the pinned version: go install github.com/pressly/goose/v3/cmd/goose@v3.28.0"; exit 2; }

# psql as the admin: provisioning only. -q keeps command tags out of the
# transcript; -v ON_ERROR_STOP=1 because a provisioning failure must abort, not
# print a warning and leave a half-built database behind a green suite.
psql_admin() { "$PSQL_BIN" -X -q -w -v ON_ERROR_STOP=1 "$ADMIN_URL" "$@"; }
# psql as the owner, used by the witness. ON_ERROR_STOP=0 because a refusal IS
# the witness — the server's own error text must reach the transcript.
psql_owner() { "$PSQL_BIN" -X -q -w -v ON_ERROR_STOP=0 "$@" ; }

# ---------------------------------------------------------------------------
# replace_once <label> <file> <old> <new> — exact, and exactly once
# ---------------------------------------------------------------------------
# A sed that matched nothing produces a green suite, and a green suite produced
# by a mutation that never applied is worse than no run at all: it reads as a
# pass. Same rule as pantry's.
replace_once() {
  local label="$1" file="$2" old="$3" new="$4" rc
  LBL="$label" FILE="$file" OLD="$old" NEW="$new" python3 - <<'PY'
import os, sys
lbl, path = os.environ["LBL"], os.environ["FILE"]
old, new = os.environ["OLD"], os.environ["NEW"]
src = open(path, encoding="utf-8").read()
c = src.count(old)
if c != 1:
    sys.stderr.write("  matched %d time(s) in %s; needed exactly 1\n" % (c, path))
    sys.exit(3)
open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
PY
  rc=$?
  [ $rc -eq 0 ] || say "ABORT  $label: the replacement did not apply exactly once (exit $rc)."
  return $rc
}

# block_confirm <file> <text> <want> <label> [note] — literal containment.
# `grep -c` counts lines, so a multi-line needle never matches one and a
# multi-line confirmation built on it silently confirms nothing.
block_confirm() {
  local file="$1" text="$2" want="$3" label="$4" note="${5:-}" got
  got=$(TEXT="$text" FILE="$file" python3 -c '
import os
print(open(os.environ["FILE"], encoding="utf-8").read().count(os.environ["TEXT"]))')
  if [ "$got" != "$want" ]; then
    say "ABORT  $label: expected $want occurrence(s) of the mutated block in ${file#$REPO/}, found $got"
    PROBLEMS=$((PROBLEMS+1)); return 1
  fi
  say "        grep-confirmed: $got occurrence(s) of the mutated block in ${file#$REPO/}$note"
  return 0
}

tree_clean() {
  local d
  for d in "${SUBJECT_DIRS[@]}"; do
    git diff --quiet -- "$d" || return 1
    git diff --quiet master -- "$d" || return 1
    [ -z "$(git status --porcelain -- "$d")" ] || return 1
  done
  return 0
}

# The instrument must not move. `restore` reverts migrations/ only; this
# fingerprints the suite so a recipe bug that edited its own measuring stick is
# caught rather than silently graded.
instrument_fingerprint() {
  local d out=""
  for d in "${INSTRUMENT_DIRS[@]}"; do
    out+="$(git hash-object $(git ls-files -- "$d" | sort) 2>/dev/null | git hash-object --stdin) "
  done
  printf '%s' "$out"
}
INSTRUMENT_BEFORE="$(instrument_fingerprint)"
instrument_intact() {
  [ "$(instrument_fingerprint)" = "$INSTRUMENT_BEFORE" ]
}

restore() {
  local label="$1"
  git checkout master -- "${SUBJECT_DIRS[@]}" 2>/dev/null
  if tree_clean; then
    RESTORED=$((RESTORED+1))
    say "        reverted from master; ${SUBJECT_DIRS[*]} byte-identical (git diff --quiet)"
  else
    RESTORE_FAILED=$((RESTORE_FAILED+1)); PROBLEMS=$((PROBLEMS+1))
    say "ABORT  $label: the tree is still dirty after the revert:"
    git --no-pager diff --stat master -- "${SUBJECT_DIRS[@]}" | sed 's/^/        /'
    return 1
  fi
  if ! instrument_intact; then
    say "ABORT  $label: the SUITE CHANGED during the run. This script must not edit ${INSTRUMENT_DIRS[*]}."
    PROBLEMS=$((PROBLEMS+1)); return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# THE SCRATCH DATABASE — drop, re-create, apply the migrations ON DISK.
# ---------------------------------------------------------------------------
db_recreate() {
  local label="$1" rc
  psql_admin -c "drop database if exists ${DBNAME} with (force)" >>"$WORK/db.log" 2>&1
  if ! psql_admin -c "create database ${DBNAME} owner identity" >>"$WORK/db.log" 2>&1; then
    say "ABORT  $label: could not create ${DBNAME}. ${WORK}/db.log has the server's answer."
    PROBLEMS=$((PROBLEMS+1)); return 1
  fi
  "$GOOSE_BIN" -dir migrations postgres "$OWNER_URL" up >>"$WORK/db.log" 2>&1
  rc=$?
  if [ $rc -ne 0 ]; then
    say "ABORT  $label: the MUTATED migrations did not apply (goose exit $rc)."
    say "        A mutation that cannot be applied is not a narrowing and must not be graded."
    tail -5 "$WORK/db.log" | sed 's/^/        /'
    PROBLEMS=$((PROBLEMS+1)); return 1
  fi
  leak_guard "$WORK/db.log"
  return 0
}

# ---------------------------------------------------------------------------
# run_suite <label> — one `go test` over the packages that can see a policy
# ---------------------------------------------------------------------------
# THE SUITE'S SCOPE IS FOUR PACKAGES, AND IT WAS CORRECTED BY A MEASUREMENT.
# The first version of this recipe ran `./internal/tenancy/` alone, on the
# stated belief that every other database test builds RLS-free clones with
# `dbtest.Schema` and therefore cannot see a policy at all. The belief is true
# of most packages and FALSE of four: `internal/accounts`, `internal/deletion`
# and `internal/recovery` carry tests that run through the service against the
# REAL protected tables as identity_app, and `*_rls_test.go` is where they say
# so. Measured, by running the whole repository against a database built from
# the N1 mutation (the SELECT policy losing identity_app) and reading the
# package lines:
#
#   FAIL  internal/accounts   internal/deletion   internal/recovery   internal/tenancy
#   ok    every other package that has tests, except the three below
#   FAIL  client             (golangci-lint is not installed in this environment)
#   FAIL  cmd/identity       (the compose boot test; environment)
#   FAIL  internal/platform/ci (substrate_copy_test byte-compares 00016's
#                              functions against kit's — it reds on EVERY
#                              substrate edit by construction, including all
#                              six mutations, and its message "cafaye.protect_table
#                              differs from kit's" is a file-shape finding, not
#                              evidence that a policy refused a legitimate
#                              principal. Excluded, named here rather than
#                              silently dropped.)
#
# A package that stays green under N1 cannot be reading the real protected
# tables AS identity_app — those reads would return zero and its assertions
# would fail — so it cannot see a policy narrowing at all. That is why the
# four packages above are the suite and the rest are not, and it is a
# measurement rather than an assumption (the first version of this file is the
# assumption, and it was wrong).
RUN_JSON=""; RUN_LOG=""; RUN_RC=0; RUN_TOTAL=0; RUN_PASS=0; RUN_FAIL=0; RUN_SKIP=0
run_suite() {
  local label="$1" line
  RUN_JSON="$WORK/$label.json"; RUN_LOG="$WORK/$label.log"
  # -p 4 for the reason bin/prime gives: the role's CONNECTION LIMIT is the
  # service's share of the shared cluster, and an unbounded run of pool-opening
  # packages fails intermittently with SQLSTATE 53300.
  ( cd "$REPO" && TEST_DATABASE_URL="$TEST_URL" REQUIRED_DB=1 \
      go test -count=1 -p 4 -json $SUITE_PKGS ) >"$RUN_JSON" 2>"$RUN_LOG"
  RUN_RC=$?
  leak_guard "$RUN_JSON" "$RUN_LOG"
  line=$(RESULTS_FILE="$RUN_JSON" python3 - <<'PY'
import json, os, sys
tot=pas=fail=skip=0
seen={}
for raw in open(os.environ["RESULTS_FILE"], encoding="utf-8"):
    try:
        ev = json.loads(raw)
    except ValueError:
        continue
    t = ev.get("Test")
    if t is None:
        continue
    a = ev.get("Action")
    if a in ("pass", "fail", "skip"):
        # count leaves only: a parent's action aggregates its subtests
        if "/" not in t:
            seen.setdefault(t, a)
for a in seen.values():
    tot += 1
    if a == "pass": pas += 1
    elif a == "fail": fail += 1
    else: skip += 1
print(tot, pas, fail, skip)
PY
)
  if [ -z "$line" ]; then
    say "ABORT  $label: go test printed no parseable result (exit $RUN_RC)."
    say "        A suite that never ran is not a green suite and is not a red one."
    tail -10 "$RUN_LOG" | sed 's/^/        /'
    PROBLEMS=$((PROBLEMS+1)); RUN_TOTAL=0; RUN_PASS=0; RUN_FAIL=0; RUN_SKIP=0
    return 1
  fi
  # shellcheck disable=SC2086
  set -- $line
  RUN_TOTAL=$1; RUN_PASS=$2; RUN_FAIL=$3; RUN_SKIP=$4
  say "        the suite -> $RUN_TOTAL tests, $RUN_PASS passed, $RUN_FAIL failed, $RUN_SKIP skipped (exit $RUN_RC)"
  return 0
}

# ---------------------------------------------------------------------------
# classify — one graded red per failing check, out of `go test -json`
# ---------------------------------------------------------------------------
# The grade of a red is read off what the SUITE RECORDED. Two record shapes:
#
#   kit's assertion set (isolation.sql) records `expected`/`actual` text. An
#   expectation of "0" or of a SQLSTATE is a REFUSAL the check demanded; any
#   other expectation ("2", "1", "alpha-1,alpha-2", "true") is a legitimate
#   operation the check required to work.
#
#   the Go tests record `t.Errorf` messages whose `want N` states what the
#   check required. `want 0`/`want none` is a refusal; a non-zero/exact `want`
#   is a legitimate operation.
#
# THE ONE NON-MECHANICAL RULE, and the measurement that puts it here, graded
# `indirect` rather than `legit` so the strong tally cannot absorb it. A
# refusal-shaped red can still be CAUSED by an over-refused legitimate write:
# mutation N4 narrows the UPDATE policy, the suite's credential revoke becomes
# a silent `UPDATE 0`, and the failure that surfaces is
#   `the ByDigest join returned 1 rows for a REVOKED key, want 0`
# — a check that can only PASS if the revoke TOOK EFFECT, so refusing more DID
# falsify it, unlike pantry's D21 (a check demanding a specific refusal
# mechanism, which refusing more can never falsify). It is graded RED-INDIRECT:
# the over-refusal was caught downstream, and no check asserts the UPDATE
# itself. Never counted with RED-LEGITIMATE. The report says why this is not
# the same shape as pantry's D21.
classify() {
  [ -f "$RUN_JSON" ] || return 0
  RESULTS_FILE="$RUN_JSON" python3 - <<'PY'
import json, os, re, sys

events = []
for raw in open(os.environ["RESULTS_FILE"], encoding="utf-8"):
    try:
        events.append(json.loads(raw))
    except ValueError:
        pass

# Output grouped by owning test; a failing test and its parent both carry text.
by_test = {}
order = []
for ev in events:
    if ev.get("Action") != "output":
        continue
    t = ev.get("Test") or "(package)"
    if t not in by_test:
        by_test[t] = []; order.append(t)
    by_test[t].append(ev.get("Output", ""))

failed = {ev.get("Test") for ev in events if ev.get("Action") == "fail" and ev.get("Test")}
if not failed:
    sys.exit(0)

kit_block = re.compile(
    r'(?m)^\s*([A-Za-z0-9_./-]+)\n'
    r'\s*expected "([^"]*)"\n'
    r'\s*actual\s+"([^"]*)"')

go_fail = re.compile(r'(?m)^\s*(\S+_test\.go:\d+):\s*(.*)')

def grade_kit(expected):
    if expected == "0":
        return "refusal", 'expectation "0" is an absence/denial'
    if re.fullmatch(r'[0-9][0-9A-Za-z]{4}', expected):
        return "refusal", 'expectation is a SQLSTATE'
    return "legit", 'expectation is a legitimate result the check required'

def grade_go(msg):
    # A refusal the SERVER ITSELF reports against a write the test needed to
    # succeed. The rule is safe because of an asymmetry in the suite rather than
    # a guess about it: every check that WANTS a refusal records the refusal
    # (cafaye_observed returns the SQLSTATE; a row-count assertion reads 0) and
    # PASSES when it happens — so a FAILING test whose message carries this
    # server error is a test that needed the write to work. Measured across the
    # four packages: it is how N5's seven reds read.
    if "violates row-level security policy" in msg:
        return "legit", "the server refused a write the check required to succeed"
    # The deletion package's three controls say this in as many words: the read
    # of the account's OWN row came back empty, so every "it survived" assertion
    # after it would be vacuous. That is a legitimate read refused.
    if "the control failed" in msg and "is not visible" in msg:
        return "legit", "the control's legitimate read of the account's own row returned nothing"
    # The accounts service answers `caller is not a member of this account` and
    # `the only owner of an account cannot change their own role` from
    # `if tag.RowsAffected() == 0` after its own UPDATE/DELETE
    # (internal/accounts/accounts.go:47,110 and store.go:271,415,762). Under N4
    # and N6 that branch is where a silently-refused legitimate write surfaces:
    # the call the test requires to succeed returns an error, and a test that
    # did not need it to succeed would not reach this line. Measured: N4's and
    # N6's reds in account_writes_rls_test.go are exactly these two sentences.
    if "caller is not a member of this account" in msg \
       or "the only owner of an account cannot change their own role" in msg:
        return "legit", "RowsAffected()==0 after a legitimate UPDATE/DELETE, read back as a domain error"
    # The N4 rule above: this sentence is true only if the revoke UPDATE wrote.
    if re.search(r'returned [1-9][0-9]* rows for a REVOKED key', msg):
        return "indirect", "true only if the legitimate revoke UPDATE took effect"
    m = re.search(r'want (neg|none|0\b|exactly \[\]|empty)', msg)
    if m:
        return "refusal", 'the check required an absence ("%s")' % m.group(1)
    m = re.search(r'want (exactly\s+\[[^\]]*\]|[^,.\n]+)', msg)
    if m:
        wanted = m.group(1).strip()
        if wanted in ("0", "0 rows"):
            return "refusal", 'the check required an absence ("%s")' % wanted
        return "legit", 'the check required a result ("want %s")' % wanted
    if re.search(r'(NOT enabled|NOT set FORCE|no index leads with account_id|enabled with no policy|is not in the public schema)', msg):
        return "catalog", "a catalog assertion, not evidence about a policy's refusals"
    return "harness", "not a check about a refusal or an allowance"

items = []
for t in order:
    if t not in failed:
        continue
    text = "".join(by_test[t])
    for m in kit_block.finditer(text):
        name, exp, act = m.group(1), m.group(2), m.group(3)
        g, why = grade_kit(exp)
        items.append((t, g, name, 'expected "%s" actual "%s" — %s' % (exp, act, why)))
    # t.Errorf/Fatalf lines; a message runs until the next file:line or the end.
    for m in go_fail.finditer(text):
        loc, msg = m.group(1), m.group(2)
        tail = text[m.end():]
        stop = re.search(r'(?m)^\s*\S+_test\.go:\d+:', tail)
        if stop:
            msg = msg + " " + tail[:stop.start()]
        msg = re.sub(r'\s+', ' ', msg).strip()
        # The kit driver's own bookkeeping (`kit's assertion set returned N
        # assertions`, `M of N account-isolation assertions failed:`) is not a
        # check — it is the summary line that PRECEDES the per-assertion blocks,
        # and grading it would report one red twice.
        if re.match(r"^kit's assertion set returned \d+ assertions", msg):
            continue
        if re.match(r"^\d+ of \d+ account-isolation assertions failed", msg):
            continue
        g, why = grade_go(msg)
        items.append((t, g, loc, msg[:220] + (' — ' + why if g != 'catalog' else '')))

for t, g, name, detail in items:
    print("\t".join((g, t, name, detail)))
PY
}

# ---------------------------------------------------------------------------
# observe <label> <mechanical expectation>
# ---------------------------------------------------------------------------
OBS_VERDICT=""; OBS_LEGIT=""; OBS_REFUSAL=""; OBS_INDIRECT=""; OBS_OTHER=""; OBS_N=0
observe() {
  local label="$1" predicted="$2" out g t name detail
  OBS_VERDICT=""; OBS_LEGIT=""; OBS_REFUSAL=""; OBS_INDIRECT=""; OBS_OTHER=""; OBS_N=0
  out=$(classify)
  if [ -z "$out" ]; then
    say "        NOT RED AT ALL: every check passed with the mutation planted."
    say "        *** THE MOST VALUABLE RESULT IN THIS RECIPE *** The suite cannot"
    say "        *** detect this narrowing, so it cannot detect an over-refusal. ***"
    NOT_RED_LEGIT=$((NOT_RED_LEGIT+1)); OBS_VERDICT="NOT-RED"
    printf '%s\t%s\t%s\t0\t-\t-\t(none) — every check passed\n' "$label" "$OBS_VERDICT" "$predicted" >>"$SUMMARY"
    return 0
  fi
  while IFS=$'\t' read -r g t name detail; do
    OBS_N=$((OBS_N+1))
    case "$g" in
      legit)    OBS_LEGIT="$OBS_LEGIT $name" ;;
      indirect) OBS_INDIRECT="$OBS_INDIRECT $name" ;;
      refusal)  OBS_REFUSAL="$OBS_REFUSAL $name" ;;
      *)        OBS_OTHER="$OBS_OTHER $name" ;;
    esac
    say "        $(printf '%-8s %s' "$g" "$name")"
    say "              $t"
    say "              $detail"
  done <<<"$out"
  if [ -n "$OBS_LEGIT" ]; then
    RED_LEGIT=$((RED_LEGIT+1)); OBS_VERDICT="RED-LEGITIMATE"
    say "        -> RED on a check asserting a LEGITIMATE operation works:$OBS_LEGIT"
  elif [ -n "$OBS_INDIRECT" ]; then
    RED_INDIRECT=$((RED_INDIRECT+1)); OBS_VERDICT="RED-INDIRECT"
    say "        -> RED on refusal-shaped checks:$OBS_REFUSAL"
    say "        -> INDIRECT, and counted separately: $OBS_INDIRECT could not pass"
    say "           unless the legitimate operation took effect, so the over-refusal WAS"
    say "           caught — downstream, and asserted nowhere. Weaker than RED-LEGITIMATE."
  else
    RED_WRONG_POLARITY=$((RED_WRONG_POLARITY+1)); OBS_VERDICT="RED-WRONG-POLARITY"
    say "        -> RED, but every red is on a check asserting a REFUSAL:$OBS_REFUSAL"
    say "        -> NOTHING PROVED by those alone: a check that wants a refusal cannot be"
    say "           falsified by refusing more. Read the report for this row."
  fi
  [ -n "$OBS_OTHER" ] && say "        -> catalog/harness-shaped reds, not evidence about a policy:$OBS_OTHER"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$OBS_VERDICT" "$predicted" "$OBS_N" \
    "${OBS_REFUSAL:-none}" "${OBS_INDIRECT:-none}" "${OBS_LEGIT:-none}" >>"$SUMMARY"
  return 0
}

# ---------------------------------------------------------------------------
# THE WITNESS — the database's own answers, on the database the suite just ran
# ---------------------------------------------------------------------------
W_A='a1000000-0000-4000-8000-0000000000a1'    # an account
W_U='a1000000-0000-4000-8000-0000000000c3'    # its owner
W_U2='a1000000-0000-4000-8000-0000000000d4'   # a second user, no membership yet
W_KEY_DIGEST='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
W_INVITE_DIGEST='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

# w_seed — the fixture every probe is a statement about. `accounts` and `users`
# are deliberately UNPROTECTED (00016's header says why), so they are seeded as
# the owner. Each protected row is seeded in its OWN transaction as
# identity_app with BOTH an account and a user identity — the shape a
# legitimate interactive write has — and that is a measurement rather than a
# preference: seeded with only the account identity, the whole fixture is
# refused by N5's narrowed INSERT policy, every probe below then reads zero for
# the wrong reason, and the witness stops isolating the mutation it is for.
# Each row prints its own command tag, so a refusal names the row it refused.
w_seed() {
  local log="$1" slug="witness-${DBNAME#identity_narrow_}" out
  : >"$log"
  out=$("$PSQL_BIN" -X -tA -w -v ON_ERROR_STOP=0 -d "$TEST_URL" 2>&1 <<SQL
begin;
insert into accounts (id, name, slug) values ('$W_A', 'Witness', '$slug');
insert into users (id, email, password_digest) values
  ('$W_U',  'witness-$slug@example.test',  'witness'),
  ('$W_U2', 'witness2-$slug@example.test', 'witness');
commit;
SQL
)
  out=$(printf '%s\n' "$out" | grep -Ev '^(BEGIN|SET|ROLLBACK|COMMIT|begin|set|rollback|commit)$|^$' | tr '\n' ' ')
  printf 'seed %-20s -> %s\n' "accounts+users" "${out:-(no output)}" >>"$log"

  w_seed_protected "$log" account_users \
    "insert into account_users (account_id, user_id, role) values ('$W_A', '$W_U', 'owner');"
  w_seed_protected "$log" api_keys \
    "insert into api_keys (user_id, account_id, name, token_digest, scopes, expires_at) values ('$W_U', '$W_A', 'witness-key', '$W_KEY_DIGEST', array['accounts:read'], now() + interval '1 day');"
  w_seed_protected "$log" account_invitations \
    "insert into account_invitations (account_id, email, role, token_digest, expires_at) values ('$W_A', 'invitee-$slug@example.test', 'member', '$W_INVITE_DIGEST', now() + interval '1 day');"
  w_seed_protected "$log" account_audit_log \
    "insert into account_audit_log (account_id, action, actor_user_id, actor_key_id, target, affected, trace_id, occurred_at) values ('$W_A', 'account.created', '$W_U', '$W_U', 'witness-audit', 0, 'witness', now());"
  leak_guard "$log"
}

w_seed_protected() {
  local log="$1" label="$2" sql="$3" out
  out=$("$PSQL_BIN" -X -tA -w -v ON_ERROR_STOP=0 -d "$TEST_URL" 2>&1 <<SQL
begin;
set local role identity_app;
select cafaye.begin_account('$W_A');
select cafaye.begin_user('$W_U');
$sql
commit;
SQL
)
  out=$(printf '%s\n' "$out" | grep -Ev '^(BEGIN|SET|ROLLBACK|COMMIT|begin|set|rollback|commit)$|^$' | tr '\n' ' ')
  printf 'seed %-20s -> %s\n' "$label" "${out:-(no output)}" >>"$log"
}

# w_probe <label> <sql> — one transaction, as identity_app, rolled back. The
# first two statements are the same pair every request's transaction opens
# with; any result is printed with its label.
w_probe() {
  local label="$1" sql="$2" out
  # `-tA` and NOT `-q`: a write's answer IS its command tag (`UPDATE 1`,
  # `INSERT 0 1`, `DELETE 1`), and psql -q suppresses exactly those — the first
  # version of this probe printed an absent tag as an empty answer, which is
  # indistinguishable from "the statement was refused".
  out=$("$PSQL_BIN" -X -tA -w -v ON_ERROR_STOP=0 -d "$TEST_URL" 2>&1 <<SQL
begin;
set local role identity_app;
$sql
rollback;
SQL
)
  out=$(printf '%s\n' "$out" | grep -Ev '^(BEGIN|SET|ROLLBACK|COMMIT|begin|set|rollback|commit)$|^$' | tr '\n' ' ')
  printf '        %-46s -> %s\n' "$label" "${out:-(no output)}"
}

# w_policy <where-clause> — the LIVE policy text, out of pg_policies. This is
# what proves a plant reached the database: `pg_policies` renders the qualifier
# the server actually holds, not the file's.
w_policy() {
  local where="$1" out
  out=$(psql_owner -d "$TEST_URL" -tA -c "
    select 'POLICY ' || tablename || ' ' || policyname || ' [' || cmd || '] roles=' ||
           array_to_string(roles, ',') || ' using=' || coalesce(qual, '-') ||
           ' check=' || coalesce(with_check, '-')
      from pg_policies
     where schemaname = 'public' and $where
     order by tablename, policyname" 2>&1)
  printf '%s\n' "$out" | sed 's/^/        /'
}

# w_witness <label> — seed, then the seven legitimate operations, then the
# live policy text for this mutation's target.
w_witness() {
  # Two `local` statements, not one: under `set -u` this bash does not expose a
  # name declared earlier in the SAME `local` statement, so
  # `local label="$1" seedlog="$WORK/$label.seed.log"` dies with
  # "label: unbound variable" — measured, on the first run of this script.
  local label="$1"
  local where="$2"
  local seedlog="$WORK/$label.seed.log"
  say "        -- WITNESS on the SAME database the suite just ran against (mutated"
  say "           migrations applied by goose; no hand-written alter policy)."
  say "        -- SEED (each protected row as identity_app, account + user identity):"
  w_seed "$seedlog"
  sed 's/^/        /' "$seedlog"
  w_probe "W1 read own audit rows (account identity)" \
    "select cafaye.begin_account('$W_A'); select count(*) from account_audit_log where account_id = '$W_A';"
  w_probe "W2 discover memberships (caller identity)" \
    "select cafaye.begin_user('$W_U'); select count(*) from account_users where user_id = '$W_U';"
  w_probe "W3 resolve own credential (digest identity)" \
    "select cafaye.begin_credential('$W_KEY_DIGEST'); select count(*) from api_keys where token_digest = '$W_KEY_DIGEST';"
  w_probe "W4 ByDigest join (credential identity)" \
    "select cafaye.begin_credential('$W_KEY_DIGEST'); select count(*) from api_keys k join account_users au on au.account_id = k.account_id and au.user_id = k.user_id where k.token_digest = '$W_KEY_DIGEST';"
  w_probe "W5 resolve own invitation (digest identity)" \
    "select cafaye.begin_credential('$W_INVITE_DIGEST'); select count(*) from account_invitations where token_digest = '$W_INVITE_DIGEST';"
  w_probe "W6 UPDATE own membership (account identity)" \
    "select cafaye.begin_account('$W_A'); update account_users set role = 'member' where account_id = '$W_A' and user_id = '$W_U';"
  w_probe "W7 INSERT own membership (account identity)" \
    "select cafaye.begin_account('$W_A'); insert into account_users (account_id, user_id, role) values ('$W_A', '$W_U2', 'member');"
  w_probe "W8 INSERT then DELETE own membership" \
    "select cafaye.begin_account('$W_A'); insert into account_users (account_id, user_id, role) values ('$W_A', '$W_U2', 'member'); delete from account_users where account_id = '$W_A' and user_id = '$W_U2';"
  say "        -- THE LIVE POLICY (pg_policies says this is what the server holds):"
  w_policy "$where"
}

# ---------------------------------------------------------------------------
# THE SIX NARROWINGS
# ---------------------------------------------------------------------------
M16="$REPO/migrations/00016_account_isolation.sql"
M18="$REPO/migrations/00018_membership_user_scope.sql"

# N1 — the SELECT policies stop naming the login role.
n1_select_drops_login_role() {
  # `protect_table` writes one policy per command `to current_user, login_role`.
  # Dropping `login_role` from the SELECT policy reads like a tidy-up ("the
  # owner is named anyway") and means identity_app has NO select policy on any
  # protected table: every read by the role production connects as returns
  # zero rows. WRITTEN FOR: kit's login/... arms and the three-way denial run
  # as identity_app.
  replace_once "N1" "$M16" \
"  execute format('create policy %I on %s for select to %I, %I using (%s)', base || '_cafaye_select', p_table, current_user, login_role, qual);" \
"  execute format('create policy %I on %s for select to %I using (%s)', base || '_cafaye_select', p_table, current_user, qual);" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for select to %I using (%s)', base || '_cafaye_select', p_table, current_user, qual);" 1 "N1" \
    " — the SELECT policy no longer names the login role" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for select to %I, %I using (%s)', base || '_cafaye_select', p_table, current_user, login_role, qual);" 0 "N1" \
    " — master's SELECT policy line is gone" || return 1
  say "        N1: <table>_cafaye_select loses identity_app; the app role reads zero rows"
}

# N2 — the credential-resolve policy demands an account identity.
n2_resolve_requires_account() {
  # `protect_credential_table` widens a read to exactly the row whose digest the
  # caller presented — the WHOLE POINT is that it runs with no account set,
  # because the account is what the lookup is FOR (MD24, and 00016's header).
  # Adding the account predicate back reads like a tightening ("resolve only
  # inside your account") and makes every scoped token resolve to zero rows,
  # which production answers as 401. WRITTEN FOR: credential_lookup_test.go's
  # `resolve the credential it presented`, credential_join_test.go's ByDigest
  # rows, invitation_resolve_test.go's resolution.
  replace_once "N2" "$M16" \
"  qual := format('%I = (select cafaye.current_credential_digest())', p_digest_column);" \
"  qual := format('%I = (select cafaye.current_credential_digest()) and account_id = (select cafaye.current_account_id())', p_digest_column);" || return 1
  block_confirm "$M16" \
"  qual := format('%I = (select cafaye.current_credential_digest()) and account_id = (select cafaye.current_account_id())', p_digest_column);" 1 "N2" \
    " — the resolve policy now also demands an account identity" || return 1
  block_confirm "$M16" \
"  qual := format('%I = (select cafaye.current_credential_digest())', p_digest_column);" 0 "N2" \
    " — master's resolve qualifier is gone" || return 1
  say "        N2: <table>_cafaye_resolve demands an account the resolution does not have"
}

# N3 — the membership-discovery policy demands an account identity.
n3_members_require_account() {
  # 00018 exists because "which accounts am I in" is asked BY a caller with no
  # account stood in; the members policy is the one that answers it. Adding the
  # account predicate reads like "discover only inside the account you are in"
  # and makes GET /v1/accounts answer the empty list — the silent defect 00018
  # was written to remove. WRITTEN FOR: profile_read_test.go's own-identity arm.
  replace_once "N3" "$M18" \
"  qual := format('%I = (select cafaye.current_user_id())', p_user_column);" \
"  qual := format('%I = (select cafaye.current_user_id()) and account_id = (select cafaye.current_account_id())', p_user_column);" || return 1
  block_confirm "$M18" \
"  qual := format('%I = (select cafaye.current_user_id()) and account_id = (select cafaye.current_account_id())', p_user_column);" 1 "N3" \
    " — the members policy now also demands an account identity" || return 1
  block_confirm "$M18" \
"  qual := format('%I = (select cafaye.current_user_id())', p_user_column);" 0 "N3" \
    " — master's members qualifier is gone" || return 1
  say "        N3: account_users_cafaye_members demands an account; discovery returns []"
}

# N4 — the UPDATE policy demands a user identity.
n4_update_requires_user() {
  # A tightening that reads like a security improvement and silently filters
  # out legitimate UPDATEs: `using` matches no row, `UPDATE 0` raises nothing,
  # and both the accounts service (which reads RowsAffected()==0 as "caller is
  # not a member") and the tenancy package's credential revoke turn into
  # refusals. WRITTEN FOR: credential_join_test's withdrawn credential and the
  # accounts package's own role-change tests under the real policies — the
  # first is an INDIRECT red, the second are checks that assert an allowed
  # ChangeRole succeeds.
  #
  # IT READS THE GUC DIRECTLY, NOT `cafaye.current_user_id()`, AND THAT IS
  # MEASURED: the reader function does not exist until 00018, so referencing it
  # from 00016's predicate aborts the whole migration —
  #   ERROR: function cafaye.current_user_id() does not exist (SQLSTATE 42883)
  # — and a mutation that cannot be applied is not a narrowing, it is a broken
  # tree. `current_setting('cafaye.user_id', true)` is NULL while the GUC is
  # unset and non-NULL once `begin_user` has run, which is the same semantics
  # the function would give, expressed with a built-in that exists from the
  # start.
  replace_once "N4" "$M16" \
"  execute format('create policy %I on %s for update to %I, %I using (%s) with check (%s)', base || '_cafaye_update', p_table, current_user, login_role, qual, qual);" \
"  execute format('create policy %I on %s for update to %I, %I using (%s and (select current_setting(''cafaye.user_id'', true)) is not null) with check (%s)', base || '_cafaye_update', p_table, current_user, login_role, qual, qual);" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for update to %I, %I using (%s and (select current_setting(''cafaye.user_id'', true)) is not null) with check (%s)', base || '_cafaye_update', p_table, current_user, login_role, qual, qual);" 1 "N4" \
    " — the UPDATE policy's USING now demands a user identity" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for update to %I, %I using (%s) with check (%s)', base || '_cafaye_update', p_table, current_user, login_role, qual, qual);" 0 "N4" \
    " — master's UPDATE policy line is gone" || return 1
  say "        N4: <table>_cafaye_update requires a user identity; legitimate UPDATEs match 0 rows"
}

# N5 — the INSERT policy's WITH CHECK gains a spurious user requirement.
n5_insert_requires_user() {
  # `with check` is the whole boundary on an INSERT (there is no `using`), so
  # this refuses every account-scoped write that does not also carry a user
  # identity — the kit proof's `login/insert-into-its-own-account-is-allowed`
  # exists for exactly this shape. WRITTEN FOR: that check, and every real-table
  # seed (each is a legitimate INSERT the tests depend on).
  replace_once "N5" "$M16" \
"  execute format('create policy %I on %s for insert to %I, %I with check (%s)', base || '_cafaye_insert', p_table, current_user, login_role, qual);" \
"  execute format('create policy %I on %s for insert to %I, %I with check (%s and (select current_setting(''cafaye.user_id'', true)) is not null)', base || '_cafaye_insert', p_table, current_user, login_role, qual);" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for insert to %I, %I with check (%s and (select current_setting(''cafaye.user_id'', true)) is not null)', base || '_cafaye_insert', p_table, current_user, login_role, qual);" 1 "N5" \
    " — the INSERT policy's WITH CHECK now demands a user identity" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for insert to %I, %I with check (%s)', base || '_cafaye_insert', p_table, current_user, login_role, qual);" 0 "N5" \
    " — master's INSERT policy line is gone" || return 1
  say "        N5: <table>_cafaye_insert demands a user identity; legitimate INSERTs are refused"
}

# N6 — the DELETE policy demands a user identity.
n6_delete_requires_user() {
  # The same tightening on the DELETE policy. WRITTEN FOR: the accounts
  # service's `RemoveMember` tests under the real policies — removal returns
  # `caller is not a member of this account` from `RowsAffected()==0`, and the
  # test that requires the removal to succeed reds. The first version of this
  # recipe ran the tenancy package alone and reported this mutation as NOT-RED;
  # the corrected scope (see run_suite) shows the service-level tests catch it.
  replace_once "N6" "$M16" \
"  execute format('create policy %I on %s for delete to %I, %I using (%s)', base || '_cafaye_delete', p_table, current_user, login_role, qual);" \
"  execute format('create policy %I on %s for delete to %I, %I using (%s and (select current_setting(''cafaye.user_id'', true)) is not null)', base || '_cafaye_delete', p_table, current_user, login_role, qual);" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for delete to %I, %I using (%s and (select current_setting(''cafaye.user_id'', true)) is not null)', base || '_cafaye_delete', p_table, current_user, login_role, qual);" 1 "N6" \
    " — the DELETE policy's USING now demands a user identity" || return 1
  block_confirm "$M16" \
"  execute format('create policy %I on %s for delete to %I, %I using (%s)', base || '_cafaye_delete', p_table, current_user, login_role, qual);" 0 "N6" \
    " — master's DELETE policy line is gone" || return 1
  say "        N6: <table>_cafaye_delete requires a user identity; legitimate DELETEs match 0 rows"
}

# ---------------------------------------------------------------------------
# one_breakage <id> <plant fn> <live-policy where> <mechanical expectation> <written for>
# ---------------------------------------------------------------------------
one_breakage() {
  local id="$1" plant="$2" where="$3" predicted="$4" written_for="$5"
  head2 "$id  —  $written_for"
  PLANTED=$((PLANTED+1))
  if ! "$plant"; then
    PLANT_FAILED=$((PLANT_FAILED+1))
    say "ABORT  $id: the mutation did not apply exactly once. NOT running the suite —"
    say "        a green over a mutation that landed nowhere reads as a pass."
    restore "$id"
    return 1
  fi
  if ! db_recreate "$id"; then restore "$id"; return 1; fi
  run_suite "$id" || { restore "$id"; return 1; }
  observe "$id" "$predicted"
  # The witness runs BEFORE the revert, on the mutated database. Skipping it on
  # a breakage that went red would be defensible and skipping it on one that
  # did not would be exactly the mistake this function exists to prevent, so it
  # runs either way.
  w_witness "$id" "$where"
  restore "$id" || return 1
  # Re-run green after every revert, on a database rebuilt from the restored
  # migrations. A breakage that is red and never restored is not a mutation
  # test, it is vandalism, and the only cheap proof that the restore took is to
  # make the suite say so again — against a database the restored files built.
  if ! db_recreate "$id-restored"; then return 1; fi
  run_suite "$id-restored" || return 1
  if [ "$RUN_FAIL" -ne 0 ]; then
    say "ABORT  $id: the suite is still red AFTER the revert. The tree did not come back."
    classify | cut -f2,3 | sed 's/^/          still failing: /'
    PROBLEMS=$((PROBLEMS+1))
    return 1
  fi
  CONTROLS_RUN=$((CONTROLS_RUN+1)); CONTROLS_GREEN=$((CONTROLS_GREEN+1))
  say "        restored: $RUN_TOTAL tests, $RUN_PASS passed, 0 failed — green again"
  return 0
}

do_control() {
  head2 "CONTROL — untouched tree, database rebuilt from master's migrations"
  CONTROLS_RUN=$((CONTROLS_RUN+1))
  db_recreate "control" || return 1
  run_suite "control-$$-$CONTROLS_RUN" || return 1
  if [ "$RUN_FAIL" -ne 0 ]; then
    say "ABORT  the control is NOT green ($RUN_FAIL failed)."
    say "        The packet's rule: if the control is not green, stop and say so."
    say "        Breakages measured against a red baseline measure nothing."
    classify | sed 's/^/          /'
    PROBLEMS=$((PROBLEMS+1))
    return 1
  fi
  CONTROLS_GREEN=$((CONTROLS_GREEN+1))
  say "        CONTROL GREEN: $RUN_TOTAL tests, $RUN_PASS passed, $RUN_FAIL failed, $RUN_SKIP skipped"
  say "        Every RED below is measured against exactly this."
  return 0
}

print_plan() {
  say "identity-narrowing-01 / narrowing — the plan"
  say ""
  say "PART 1 — six NARROWINGS. Each must go red on a check asserting a"
  say "         LEGITIMATE operation works; a red on a refusal check proves nothing."
  say "  N1  00016 protect_table       SELECT policy stops naming identity_app"
  say "                                 [every app-role read returns 0 rows]"
  say "  N2  00016 protect_credential_table  resolve policy + account predicate"
  say "                                 [every scoped token stops resolving]"
  say "  N3  00018 protect_membership_table  members policy + account predicate"
  say "                                 ['which accounts am I in' returns []]"
  say "  N4  00016 protect_table       UPDATE policy + user-identity clause"
  say "                                 [the accounts role-change tests and the"
  say "                                  tenancy revoke silently no-op]"
  say "  N5  00016 protect_table       INSERT WITH CHECK + user-identity clause"
  say "                                 [the allowed-insert check refuses]"
  say "  N6  00016 protect_table       DELETE policy + user-identity clause"
  say "                                 [the accounts RemoveMember tests refuse]"
  say ""
  say "Each breakage: grep-confirmed applied -> disposable DB rebuilt with goose ->"
  say "suite -> WITNESS on that same DB -> restore -> rebuilt from master -> suite green."
  say "A breakage that does NOT go red is printed loudly. That is a result."
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if [ "$PHASE" = "list" ]; then print_plan; exit 0; fi

say "identity-narrowing-01 / narrowing"
say "repo:   $REPO"
say "branch: $(git rev-parse --abbrev-ref HEAD) @ $(git rev-parse --short HEAD)"
say "suite:  go test -count=1 -json ${SUITE_PKGS} (REQUIRED_DB=1)"
say "db:     ${DBNAME} (owner identity, admin the provided admin role; dropped on exit)"
say "witness fixtures: account ${W_A}, users ${W_U}/${W_U2} — fixed ids, so every diff is the policy"

if ! tree_clean; then
  say "ABORT  ${SUBJECT_DIRS[*]} is not clean at the start of the run."
  say "        A mutation recipe that starts from a dirty tree cannot tell its own"
  say "        damage from somebody else's. Commit or stash first."
  git --no-pager diff --stat master -- "${SUBJECT_DIRS[@]}" | sed 's/^/        /'
  exit 2
fi
say "instrument fingerprint: ${INSTRUMENT_BEFORE:-（none）} (${INSTRUMENT_DIRS[*]})"

db_cleanup() {
  [ "$KEEP_DB" -eq 1 ] && { say "leaving ${DBNAME} behind (--keep-db)"; return 0; }
  case "$DBNAME" in
    identity_narrow_*) psql_admin -c "drop database if exists ${DBNAME} with (force)" >>"$WORK/db.log" 2>&1 ;;
    *) say "not dropping $DBNAME: it is not a name this script creates" ;;
  esac
}
trap 'db_cleanup' EXIT INT TERM

do_control || {
  say ""
  say "narrowing.sh: the control did not pass, so nothing was planted."
  say "Exiting non-zero without having broken anything."
  exit 1
}

if [ "$PHASE" = "all" ] || [ "$PHASE" = "part1" ]; then
  say ""
  say "== WITNESS BASELINE — master's migrations, untouched. Every witness below"
  say "   is a diff against this, because 'every check passed' is also what a"
  say "   mutation that changed nothing at runtime prints."
  w_policy "policyname like '%_cafaye_%'"
  w_witness "baseline" "policyname like '%_cafaye_%'"
  say ""
  say "PART 1 — six narrowings"
  one_breakage N1 n1_select_drops_login_role "policyname like '%_cafaye_select'" \
    "kit's login/... arms narrow; app-role reads return 0" \
    "the SELECT policy stops naming the login role" || true
  one_breakage N2 n2_resolve_requires_account "policyname like '%_cafaye_resolve'" \
    "credential and invitation resolutions narrow" \
    "the resolve policy demands an account identity" || true
  one_breakage N3 n3_members_require_account "policyname = 'account_users_cafaye_members'" \
    "the own-identity membership arm narrows" \
    "the members policy demands an account identity" || true
  one_breakage N4 n4_update_requires_user "policyname like '%_cafaye_update'" \
    "the accounts role-change tests and the tenancy revoke silently no-op" \
    "the UPDATE policy demands a user identity" || true
  one_breakage N5 n5_insert_requires_user "policyname like '%_cafaye_insert'" \
    "the allowed-insert check refuses" \
    "the INSERT policy's WITH CHECK demands a user identity" || true
  one_breakage N6 n6_delete_requires_user "policyname like '%_cafaye_delete'" \
    "the accounts RemoveMember tests refuse" \
    "the DELETE policy demands a user identity" || true
fi

head2 "FINAL VERIFICATION"
if do_control; then
  say "        FINAL CONTROL GREEN: $RUN_TOTAL tests, $RUN_PASS passed, $RUN_FAIL failed"
else
  say "ABORT  the final control is NOT green. The recipe did not restore the tree."
fi

rule
if tree_clean; then
  say "git diff --quiet master -- migrations/   ->  CLEAN (no differences from master)"
  say "git diff --quiet -- migrations/          ->  CLEAN (nothing unstaged)"
  say "git status --porcelain -- migrations/    ->  empty (nothing untracked)"
else
  say "git diff --quiet master -- migrations/   ->  DIRTY"
  git --no-pager diff --stat master -- "${SUBJECT_DIRS[@]}" | sed 's/^/        /'
  PROBLEMS=$((PROBLEMS+1))
fi
if instrument_intact; then
  say "instrument fingerprint unchanged          ->  ${INSTRUMENT_DIRS[*]} untouched"
else
  say "instrument fingerprint CHANGED            ->  the suite was edited; this run is not a result"
  PROBLEMS=$((PROBLEMS+1))
fi

rule
say "TALLIES — breakages planted and reds observed are different numbers and are"
say "         never added together. So are controls and passes."
printf 'controls run (every one green):        %s\n' "$CONTROLS_RUN"
printf 'breakages planted:                     %s\n' "$((PLANTED-PLANT_FAILED))"
printf '  of which the plant FAILED:           %s\n' "$PLANT_FAILED"
printf 'breakages reverted byte-for-byte:      %s\n' "$RESTORED"
printf 'breakages red on a LEGITIMATE op:      %s      <- the owed condition\n' "$RED_LEGIT"
printf 'breakages red only INDIRECTLY:         %s      <- caught downstream, asserted nowhere\n' "$RED_INDIRECT"
printf 'breakages red only on refusal checks:  %s\n' "$RED_WRONG_POLARITY"
printf 'breakages NOT RED AT ALL:              %s\n' "$NOT_RED_LEGIT"
printf 'structural problems:                   %s\n' "$PROBLEMS"
say ""
printf '%-4s %-19s %-6s %-30s %-24s %s\n' ID OUTCOME REDS "REFUSAL-SHAPED" "INDIRECT" "LEGITIMATE-OP CHECKS"
while IFS=$'\t' read -r a b c d e f g; do
  printf '%-4s %-19s %-6s %-30s %-24s %s\n' "$a" "$b" "$d" "${e:-none}" "${f:-none}" "${g:-none}"
done <"$SUMMARY"

say ""
if [ "$PROBLEMS" -eq 0 ]; then
  say "ok — control green, every plant applied exactly once, every revert byte-identical,"
  say "     the suite green again after each, and no log carried a credential."
  say "     Read the table above for whether anything noticed."
  exit 0
fi
say "FAIL — $PROBLEMS structural problem(s). This run is not a result. Logs in $WORK"
KEEP_DB=1
exit 1
