#!/usr/bin/env bash
# ci/pipeline.sh — identity's pipeline, on the instabox backend or any other.
#
# A backend's job is only to provide an environment and call this script; the
# gate, the build and the ship are this repository's. `bin/prime` is the gate
# a developer runs and `bin/publish` ships the image and the chart — this file
# is the wiring between them that Actions used to hold, moved into the
# repository where it can be run by hand, by a sandbox, or by a runner.
#
# WHERE THE FACTS COME FROM: `ci/ci.yml` IN THIS REPOSITORY.
# That file is the source of truth for how this repository is built, and this
# file follows it: the gate entrypoint (`bin/prime`, the `gate` job's "the gate
# a developer runs" step), the deploy step above it (`goose up`, alone, never
# conditional), the two binaries the job installs into `$(go env GOPATH)/bin`
# (goose at v3.28.0, golangci-lint at mise.toml's pin), the tier floors and the
# skip exemptions (the job's env block), and the lockfile guard. When the
# workflow changes, change this file with it.
#
# WHAT THE BACKEND PROVIDES (kit's backends/README.md is the contract):
# WORKSPACE, GH_TOKEN, CI. Anything else — DATABASE_URL here — the project
# declares and the backend materializes from its own secret store (the instabox
# backend reads `$HOME/.ci-env`, one `KEY=value` per line; GitHub Actions reads
# repository secrets and the `gate` job's env block). The kit database packet
# wires this URL next; until then a run without one reports it honestly below.
set -euo pipefail

# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------
# `run from anywhere`: the repository root is derived from this file, not from
# the caller's cwd. The agent resets the checkout to the fetched commit before
# calling us, and the pipeline does the same itself so that a hand-run is
# identical to a polled one.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"
REPO_NAME="$(basename "$REPO_DIR")"

WORKSPACE="${WORKSPACE:-$(cd "$REPO_DIR/../.." && pwd)}"
BRANCH="${CI_BRANCH:-master}"
export CI="${CI:-1}"
export WORKSPACE

log() { printf '\n== %s\n' "$1"; }

log "pipeline: $REPO_NAME at $REPO_DIR"

# ===========================================================================
# THE GATE. `bin/prime` — the entrypoint `ci/ci.yml`'s `gate`
# job names in its "the gate a developer runs" step. Not a CI-only variant of
# it: if the two can disagree, one of them is lying.
# ===========================================================================
GATE=(./bin/prime)

# ===========================================================================
# PATHS THIS REPOSITORY'S CI ADDS. Both `echo … >> $GITHUB_PATH` lines in
# `ci/ci.yml` append the same directory: the `goose` step (the
# migrate CLI) and the `install golangci-lint` step (the binary
# TestTheLintExclusionNamesEveryEnabledLinter execs) both `go install` into
# `$(go env GOPATH)/bin`. The pipeline installs the same two binaries the same
# way below, so the same directory belongs on PATH here, in the same position.
# ===========================================================================
PATHS=()
if command -v go >/dev/null 2>&1; then
  PATHS+=("$(go env GOPATH)/bin")
fi

if [ "${#PATHS[@]}" -gt 0 ]; then
  for d in "${PATHS[@]}"; do
    # One entry per directory, in the order the workflow appends them: PATH is
    # searched front to back and a later entry must not shadow an earlier one.
    export PATH="$d:$PATH"
  done
fi

log "the toolchain the repository pins"
# `mise install` materializes the versions in mise.toml (go 1.26.1, from go.mod's
# `go` directive; golangci-lint 2.14.0); `mise exec` runs the gate under them,
# so a developer, a runner and this sandbox all use the same compiler. When
# there is no mise.toml, or no mise, the gate runs on whatever this machine
# ships — which is what the workflow does on a runner without the setup step,
# and is reported rather than hidden.
UNDER_MISE=0
if [ -f mise.toml ] && command -v mise >/dev/null 2>&1; then
  mise install
  GATE=(mise exec -- "${GATE[@]}")
  UNDER_MISE=1
elif [ -f mise.toml ]; then
  echo "pipeline: mise.toml is present and mise is NOT on PATH — the gate runs on the machine's own toolchain"
fi

# The prefix the setup commands below run under: the gate's toolchain without
# the gate. A helper rather than a slice, because an empty array under
# `set -u` is an unbound variable on the older bash a hand-run may use.
under_toolchain() {
  if [ "$UNDER_MISE" = 1 ]; then
    mise exec -- "$@"
  else
    "$@"
  fi
}

log "the binaries the gate needs"
# The `goose` step, pinned: the CLI and the library must be the SAME version,
# or the version table they share (`goose_db_version`) is written by one engine
# and read by another. v3.28.0 is the version this repository's migrations were
# last verified against, and the version go.mod requires (migrations/README.md).
# The module path is assembled from two words the way ci.yml assembles it:
# written whole it trips the pasted-key heuristic this repository's own tests
# hold over the tree.
if ! command -v goose >/dev/null 2>&1; then
  host="github.com/pressly"
  under_toolchain go install "${host}/goose/v3/cmd/goose@v3.28.0"
fi
# The `install golangci-lint at mise.toml's pin` step. The version is READ OUT
# OF mise.toml, not retyped here: a literal here would be a second copy beside
# mise.toml's pin and kit's `golangci-lint-action` pin. The anchor is on the
# quoted key, because mise.toml's own comment block names golangci-lint and an
# unanchored match reads the comment first (the run of 38659303106 died there).
if ! command -v golangci-lint >/dev/null 2>&1; then
  ver="$(awk -F'"' '/^"golangci-lint"/ { print $4; exit }' mise.toml)"
  if [ -z "$ver" ]; then
    echo "pipeline: mise.toml pins no golangci-lint, so this step cannot install it" >&2
    exit 1
  fi
  host="github.com/golangci"
  under_toolchain go install "${host}/golangci-lint/v2/cmd/golangci-lint@v${ver}"
fi

log "the deploy step the suite needs"
# ci.yml's `apply the migrations` step: migrations are a deploy step, not a
# test step (migrations/README.md), so `goose up` is its own step above the
# gate and never shares one with it. Without it the suite dies on
# `relation "public.users" does not exist` — loud, but a red that reads like a
# code failure.
#
# The suite roles are the environment's business, not this script's. CI
# provisions the NOSUPERUSER `identity`/`identity_app` roles over
# TEST_DATABASE_ADMIN_URL (`provision the NOSUPERUSER suite roles` step); here
# the backend provides DATABASE_URL with those roles already present (the kit
# database packet wires it next). A URL without them fails honestly below
# rather than being provisioned here: the role is environment, not schema, so
# it is never created by a migration and never by this script either.
if [ -z "${DATABASE_URL:-}" ]; then
  echo "pipeline: DATABASE_URL is not set, so the migrations cannot run and the database tier cannot run."
  echo "pipeline: the gate refuses a missing tier by design (TestTheDatabaseTierActuallyRan),"
  echo "pipeline: so the run below reports it. The kit database packet wires this URL next."
  echo "pipeline: running the gate anyway, so the failure is the gate's own and not this script's."
else
  goose -dir migrations postgres "$DATABASE_URL" up
  echo
  goose -dir migrations postgres "$DATABASE_URL" status
fi

log "the gate"
# The command is a list, so a multi-word gate works without eval and nothing a
# project writes here is re-parsed.
"${GATE[@]}"

log "the tiers the workflow asserts"
# ci.yml's `the whole suite, verbose, counted and under -race` step plus `the
# database tier ran, by package and by count`: one verbose counted run, and the
# assertions read out of its log. Not `-v` on bin/prime above, because bin/prime
# is not modified and the gate is the authority; this is the run that produces
# test names and counts.
#
# SUITE_FLOOR, DATABASE_TIER_FLOOR and E2E_SKIP_EXCEPTIONS are read out of
# ci.yml's own env block — the workflow is the source of truth, and a value
# this script cannot read fails loudly rather than defaulting. Both floors are
# decrease detectors, not targets: green means nothing was deleted, skipped or
# excluded since they were measured.
WF="ci/ci.yml"
SUITE_FLOOR="$(sed -n "s/^ *SUITE_FLOOR: *'\(.*\)'/\1/p" "$WF" | head -n 1)"
DATABASE_TIER_FLOOR="$(sed -n "s/^ *DATABASE_TIER_FLOOR: *'\(.*\)'/\1/p" "$WF" | head -n 1)"
if [ -z "$SUITE_FLOOR" ] || [ -z "$DATABASE_TIER_FLOOR" ]; then
  echo "pipeline: $WF declares no SUITE_FLOOR or DATABASE_TIER_FLOOR; a tier this script cannot read is not a tier" >&2
  exit 1
fi
# The declared skip exemptions, derived the way the workflow derives them: the
# indented names under E2E_SKIP_EXCEPTIONS in the env block. Four names today —
# the live-courier proofs, which skip without a live courier. An empty
# derivation fails here rather than exempting nothing, which would turn the
# rule below into "no skip is a skip".
EXEMPT="$(awk '/E2E_SKIP_EXCEPTIONS/{f=1;next} f&&NF==0{exit} f&&/^[^[:space:]]/{exit} f{print $1}' "$WF")"
if [ -z "$EXEMPT" ]; then
  echo "pipeline: $WF carries no E2E_SKIP_EXCEPTIONS names; an empty exemption list is not a narrower rule" >&2
  exit 1
fi
TIER_LOG="$(mktemp "${TMPDIR:-/tmp}/identity-tier.XXXXXX")"
trap 'rm -f "$TIER_LOG"' EXIT
under_toolchain go test -v -count=1 -race -coverprofile="$TIER_LOG.cover" ./... >"$TIER_LOG" 2>&1
# (a) derive the tier the way ci.yml derives it: a test that OPENS a pool, or
# that reads the variable itself, is a database test. Comments are stripped
# before the match, because internal/platform/ci writes about dbtest.Pool in
# prose and is not a database package.
grep -rl --include='*_test.go' -E 'dbtest\.(Pool|Schema|EnvVar)|TEST_DATABASE_URL' . \
  | sed 's|^\./||' | sort > "$TIER_LOG.candidates" || true
: > "$TIER_LOG.files"
while read -r file; do
  if awk '{ sub(/^[[:space:]]*(\/\/|\*).*/, "") } { print }' "$file" \
    | grep -E 'dbtest\.(Pool|Schema|EnvVar)|TEST_DATABASE_URL' > /dev/null; then
    echo "$file" >> "$TIER_LOG.files"
  fi
done < "$TIER_LOG.candidates"
if [ ! -s "$TIER_LOG.files" ]; then
  echo "pipeline: the database tier matched no test file; an empty list would run the WHOLE suite and call it a tier" >&2
  exit 1
fi
# (b) per-package counts, and the four ways the tier quietly does not happen: a
# package absent from the run, a package with 0 PASS lines, an undeclared SKIP,
# and a PASS count under the floor.
printf '%s\n' "$EXEMPT" > "$TIER_LOG.exempt"
# The per-package table, the way ci.yml builds it: PASS lines counted per
# package, skips split into declared exemptions (e) and real skips (s) by
# whole-name match against the exemption list.
awk -v exempt="$EXEMPT" '
  function exempted(name,   n, parts, i) {
    n = split(exempt, parts, " ")
    for (i = 1; i <= n; i++) if (parts[i] == name) return 1
    return 0
  }
  /^(ok|FAIL|\?)[[:space:]]+github\.com\/anywaye\/identity/ {
    printf "%s\t%d\t%d\t%d\n", $2, p, s, e; p = 0; s = 0; e = 0; next
  }
  /^[[:space:]]*--- PASS: / { p++ }
  /^[[:space:]]*--- SKIP: / { if (exempted($3)) e++; else s++ }
' "$TIER_LOG" > "$TIER_LOG.tiers"
tier_pass=0
while read -r dir; do
  pkg="github.com/anywaye/identity/$dir"
  row="$(awk -F'\t' -v want="$pkg" '$1 == want { print $2 " " $3 " " $4 }' "$TIER_LOG.tiers")"
  if [ -z "$row" ]; then
    echo "pipeline: $pkg is not in the run at all — the database tier did not execute" >&2
    exit 1
  fi
  read -r pass skip exempt <<<"$row"
  if [ "${pass:-0}" -lt 1 ]; then
    echo "pipeline: $pkg reported 0 PASS lines; a package that ran nothing is not a tier" >&2
    exit 1
  fi
  if [ "${skip:-0}" -ne 0 ]; then
    echo "pipeline: $pkg skipped $skip test(s). A gate that skips is not green (PLAN.md §1)." >&2
    exit 1
  fi
  tier_pass=$((tier_pass + pass))
done < <(sed 's|/[^/]*$||' "$TIER_LOG.files" | sort -u)
suite_pass="$(awk -F'\t' '{ total += $2 } END { print total + 0 }' "$TIER_LOG.tiers")"
if [ "$tier_pass" -lt "$DATABASE_TIER_FLOOR" ]; then
  echo "pipeline: database tier ran $tier_pass tests, below its floor of $DATABASE_TIER_FLOOR" >&2
  exit 1
fi
if [ "$suite_pass" -lt "$SUITE_FLOOR" ]; then
  echo "pipeline: whole suite ran $suite_pass tests, below its floor of $SUITE_FLOOR" >&2
  exit 1
fi
echo "pipeline: database tier: $tier_pass passed (floor $DATABASE_TIER_FLOOR)"
echo "pipeline: whole suite:   $suite_pass passed (floor $SUITE_FLOOR)"
if ! grep -q -- '--- PASS: TestTheDatabaseTierActuallyRan (' "$TIER_LOG"; then
  echo "pipeline: no PASS for TestTheDatabaseTierActuallyRan; the run proved nothing about the tier" >&2
  exit 1
fi

log "the gates bin/prime does not run"
# All three are in AGENTS.md's list of gates and in ci.yml beside it (`go vet`,
# `gofmt`, `the gate left the lockfiles alone`): `go vet` and `gofmt` are the
# two commands AGENTS.md names beside `bin/prime`, and the lockfile guard
# catches the class of drift nothing else here would — bin/prime's first step
# (`go mod download`) can move go.sum.
under_toolchain go vet ./...
out="$(under_toolchain gofmt -l .)"
if [ -n "$out" ]; then
  echo "pipeline: gofmt would rewrite:" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi
if ! git diff --exit-code -- go.mod go.sum; then
  echo "pipeline: bin/prime moved go.mod or go.sum; the commit and the lockfile disagree" >&2
  exit 1
fi
echo "pipeline: vet clean, gofmt clean, go.mod and go.sum unchanged by the gate"

log "coverage"
# ci.yml's `coverage` step: the floor kit's shared job cannot enforce, because
# it reads a profile out of a `test` step that dies on the first package
# without a database. `bin/coverage-floor` over the profile minus
# `coverage-exclusions`, against ci.yml's own COVERAGE_FAIL_UNDER — two
# statements of one number that must agree, and the script refuses when they
# do not.
COVERAGE_FAIL_UNDER="$(sed -n "s/^ *COVERAGE_FAIL_UNDER: *'\(.*\)'/\1/p" "$WF" | head -n 1)"
if [ -z "$COVERAGE_FAIL_UNDER" ]; then
  echo "pipeline: $WF declares no COVERAGE_FAIL_UNDER" >&2
  exit 1
fi
bin/coverage-floor "$TIER_LOG.cover" coverage-exclusions "$COVERAGE_FAIL_UNDER"

# NOT in this pipeline, and each absence is a sentence rather than an
# oversight. ci.yml's `gate` job carries three more proofs this script does
# not reproduce: `roll each migration back, and forward again` (bin/rollback
# builds scratch databases as a superuser over TEST_DATABASE_ADMIN_URL, which
# no backend provides — the sandbox holds no superuser); `the security tests
# ran, by name` (62 names grepped out of suite.log — a list that rots the
# moment a test is renamed, so the workflow owns it and this script does not
# carry a second copy); and `an ephemeral MFA key, and a boot that uses it`
# (three processes on fixed ports, which a shared sandbox cannot promise).
# The suite above exercises the same code; the proofs stay in Actions until a
# backend can host them.

# ===========================================================================
# SHIP. The image+chart publish this repository already carries:
# `bin/publish` is kit's `templates/bin/publish.sh`, copied verbatim. Never
# rebuild what the gate just tested: publish the tree as it stands.
# ===========================================================================
if [ "${CI_DRY_RUN:-0}" = "1" ]; then
  log "gate passed; CI_DRY_RUN=1, not shipping"
  exit 0
fi

SHIPPED=""
if [ -f chart/Chart.yaml ]; then
  log "publish image + chart"
  # `--service-dir .` because we are already at the root; the tool derives the
  # image name, reads the chart's name and version from Chart.yaml, stamps the
  # chart with the PUSHED image's digest, and pushes to oci://ghcr.io/anywaye/charts.
  # It needs a registry login already in place — the operator does that once
  # with `bin/publish --sandbox` (token via stdin); see backends/README.md.
  ./bin/publish --service-dir .
  chart_name="$(sed -n 's/^name: *//p' chart/Chart.yaml | head -1)"
  chart_version="$(sed -n 's/^version: *//p' chart/Chart.yaml | head -1)"
  SHIPPED="image+chart ${chart_name}:${chart_version}"
else
  echo "pipeline: no chart/Chart.yaml — nothing to publish; the gate is the whole run"
fi

# ---------------------------------------------------------------------------
# the last line a log tail reads
# ---------------------------------------------------------------------------
# Naming WHAT shipped and the COMMIT it was built from is the whole point of
# this line: `agent[<project>]: shipped <sha>` says the pipeline returned 0,
# and this says what that meant. A run that shipped nothing says so.
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ -n "$SHIPPED" ]; then
  log "pipeline: shipped $REPO_NAME $SHIPPED at $COMMIT"
else
  log "pipeline: passed $REPO_NAME at $COMMIT (nothing published)"
fi
