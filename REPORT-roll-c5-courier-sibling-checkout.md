# REPORT roll-c5-courier-sibling-checkout — the gate's sibling checkout was a step the action refuses to run

## 1. The defect, measured

The ci-tools packet landed with the courier sibling checked out by
`actions/checkout@v7` at `path: ../courier`. `actions/checkout@v7` refuses any
path outside `$GITHUB_WORKSPACE`, and the gate job died before the gate started.
Live, on the merge of `roll-c5-identity-ci-tools` (identity CI run **38657748356**,
job `gate (bin/prime, migrations, tiers, lockfile)`):

```
##[group]Run actions/checkout@v7
with:
  repository: cafaye/courier
  ref: 5c29dfb2d5e32dd6e96db4000f25fb69adaf23fd
  path: ../courier
##[error]Repository path '/home/runner/work/identity/courier' is not under '/home/runner/work/identity/identity'
```

and then, downstream, `##[error]No files were found with the provided path:
/home/runner/work/_temp/suite.log` — the suite never wrote its log because the
gate step that produces it ran against a missing sibling.

The path was not negotiable: `internal/courier/recorded_test.go`'s
`sourceCheckoutCourier` resolves the MAIN checkout's parent through
`git rev-parse --git-common-dir`, so the sibling has to be at
`<workspace>/../courier`; and a checkout INSIDE the tree puts a foreign tree in
the way of `go vet ./...`, `gofmt -l .` and the lockfile guard. The packet's
local verification could not catch this: `git` itself has no such guard, and
every local run had the sibling already beside the checkout.

## 2. What changed

`git` has no workspace-containment guard, so the checkout is a `run:` step the
workflow owns:

```yaml
      - name: check out courier beside the tree, at the pin
        env:
          COURIER_DIR: ${{ github.workspace }}/../courier
        run: |
          set -euo pipefail
          git clone --quiet https://github.com/cafaye/courier "$COURIER_DIR"
          git -C "$COURIER_DIR" checkout --quiet --detach "$COURIER_REF"
```

- **The pin is unchanged**: `$COURIER_REF` is the same environment value the
  `read courier.ref` step above already exports from `courier.ref`
  (`5c29dfb2d5e32dd6e96db4000f25fb69adaf23fd`), and the clone is explicitly
  detached onto it — never left on the clone's default branch.
- **The location is unchanged**: `${{ github.workspace }}/../courier`, the same
  directory `path: ../courier` named, which is what `sourceCheckoutCourier`
  resolves.
- **An unauthenticated clone reaches it**: `cafaye/courier` is PUBLIC; no
  credential, no token, no permission widening.

`internal/platform/ci/ci_test.go`'s `TestTheGateChecksOutCourierBesideTheTree`
was reshaped to hold the same three claims where they now live — the repository
and the pin in the step's script (`git clone` + `cafaye/courier`, consuming
`COURIER_REF`), the beside-the-tree location in the step's `env:` line, and the
40-character pin shape in `courier.ref` (mechanism-independent, unchanged). Its
comment records the live `actions/checkout@v7` error this step exists because of.

## 3. Controls

- **Simulated CI layout, from the branch**: a fresh clone of this repository at
  `/tmp/ci-sim/identity`, the workflow's own two commands run verbatim with
  `COURIER_DIR=/tmp/ci-sim/courier`:
  - `TestCouriersTypesAgreeWithCouriersDocument` — PASS, and its success line
    names the file it read: `courier's NotificationType enum in
    /tmp/ci-sim/courier/openapi.yaml equals this package's 6 Type* constants`.
    The sibling resolved through `git rev-parse --git-common-dir` exactly as the
    test documents.
  - `TestTheGateChecksOutCourierBesideTheTree` — PASS against the new step.
- **Full gate**: `bin/prime` (below), against the real database, with
  golangci-lint on PATH.
- The old mechanism was **proven red live** — that is section 1, not a mock.

## 4. What was not done

- The `ci (kit: go)` job's own two reds are untouched and unchanged: its `test`
  step cannot have a Postgres (a reusable workflow cannot host a service
  container — documented in `.github/workflows/ci.yml`'s header), and its `lint`
  step reports 5 findings with kit's config (`internal/outbox/nats_reconnect_test.go`:
  misspell 3, noctx 1, revive 1). That job is known-red on arrival by the file's
  own header, `gate` is the required job, and the 5 findings are left for a
  packet that can also carry the job to green.
- No other job's steps were touched; the two `uses: actions/checkout@v7` steps
  that check out THIS repository (inside the workspace) are fine as they are.

## 5. The second live failure, and it was found the same way

With the checkout repaired, the gate job ran further and died in the ci-tools
packet's other new step — the linter install. Run **38659303106**, job `gate`:

```
##[error]mise.toml pins no golangci-lint, so this step cannot install it
```

on a mise.toml that pins `"golangci-lint" = "2.14.0"`. The step's read was

```
ver="$(awk -F'"' '/golangci-lint/ { print $4; exit }' mise.toml)"
```

and mise.toml's comment block above the pin NAMES golangci-lint — so the awk's
first match was the comment line `# golangci-lint is the binary …`, which carries
no double quote, `$4` came back empty, and the step refused on a file that pins
the tool. Reproduced locally by running the program verbatim:

```
$ awk -F'"' '/golangci-lint/ { print "line:", $0; print "field4:[" $4 "]"; exit }' mise.toml
line: # golangci-lint is the binary `TestTheLintExclusionNamesEveryEnabledLinter`
field4:[]
```

The read is now anchored on the quoted key's line —
`'/^"golangci-lint"/'`, which resolves `2.14.0` — and
`TestTheGateInstallsTheLinterBeforeTheSuite` grew a fourth assertion that the
step's script carries that anchor, with the failure mode in the message. Both of
the ci-tools packet's new gate steps have now failed live once, in ways no local
run could see; that is the packet's real finding.
