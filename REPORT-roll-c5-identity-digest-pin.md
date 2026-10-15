# REPORT — roll-c5-identity-digest-pin

**The packet.** identity is one of the seven service repositories that never
adopted the template half of kit's image-digest pin. Kit's publish path has
written `image.digest` into a chart's `values.yaml` before `helm package` on
every `push: true` run since `roll-c5-image-digest`, and this chart's
Deployment rendered `{{ .Values.image.repository }}:{{ .Values.image.tag }}`
and never read the field — so a digest-pinned chart rendered an unchanged
spec, Argo's diff reported `Synced`, and the box kept the old image. Measured
in kit's own contract (quoted in §2): the registry held `sha256:c264…37165`
while the node ran `sha256:8e60…e79b`, six hours after the fix was published.
This packet makes the pin reach the pod, and proves both renders.

Branch `feat/digest-pin`, worktree
`/Users/kaka/Code/any/moon/wt/adopt-digest-identity`, cut from current master
(`a3facb3`). Nothing pushed, nothing merged, no other repository touched. The
worktree held no uncommitted partial work from the previous attempt — `git
status` was clean and the branch pointed at master's own commit. Kit was read,
never written: `/Users/kaka/Code/any/moon/cafaye/kit` at its `master`.

---

## 1. The contract, quoted

`cafaye/kit/.github/workflows/chart.reusable.yml`, seam 3, lines 58–76:

> **THE IMAGE DIGEST — THE ONE THAT REACHES THE POD, AND THE ONE THAT WAS
> MEASURED MISSING.** The `appVersion` tag is overwritten on every push (it is
> this workflow's own hand-off, re-published per master push), and charts
> pinned the image by that tag: the rendered Deployment was textually
> IDENTICAL before and after a build, so Argo's diff reported `Synced`, rolled
> nothing, and the box sat on the old image while the registry held the new
> one. Measured (roll-c5-image-digest): the registry's
> `ghcr.io/cafaye/gateway:0.1.0` held `sha256:c264…37165` while the node ran
> `sha256:8e60…e79b`, six hours after the fix was merged and published; a
> refresh reported `Synced` with no diff and `imagePullPolicy: IfNotPresent`
> re-served the stale copy on every pod restart. A DIGEST cannot move, so this
> workflow writes the digest of the image the compose run just built into the
> chart's `values.yaml` (`image.digest`) BEFORE `helm package`: the chart that
> lands in the OCI registry names the bytes the registry holds beside it, a
> new build is a textual diff Argo rolls, and the chart VERSION (seam 2) does
> not move — the substrate Application's targetRevision is untouched. The
> composer hands the digest down; see `publish.reusable.yml`, the only party
> that knows both ends.

The step itself, `chart.reusable.yml` lines 277–302:

> **PIN THE IMAGE BY DIGEST** — the step that makes a new build a change Argo
> can SEE. … The chart pinned the image by TAG, the tag is overwritten on
> every master push, so the rendered Deployment was textually identical before
> and after the build: Argo's diff reported `Synced`, rolled nothing, and
> `IfNotPresent` re-served the node's stale copy on every restart. The digest
> is the one image name that cannot move, so it is written into the chart
> BEFORE the chart is packaged — a package is a tarball of the directory, so
> an edit after `helm package` would pin nothing.
>
> **IT REFUSES RATHER THAN WRITES A MALFORMED DIGEST:** a value that is not
> `sha256:<64 hex>` would render `repository@nonsense`, which looks like a pin
> and fails at image-pull with nothing naming this step. `sha256:` plus 64
> lowercase hex is the registry's own manifest digest grammar, the same shape
> gateway's own gate asserts (`bin/prime-go`) at the chart end.

The step's own words about this repository (chart.reusable.yml lines 348–351,
the INSERT branch — the half that fires for a chart that has not adopted the
field, i.e. this one until now):

> INSERT it, for a chart that has not adopted the field yet: the publish pins
> what the template can read, and **a deployment that does not render
> image.digest ignores a value it never reads.**

The refusal it enforces at the write (line 315):

> `if ! printf '%s' "$IMAGE_DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$'; then`

And the composer that feeds it, `publish.reusable.yml` lines 81–102 and 275:

> **3b. THE IMAGE DIGEST — THE OTHER HALF OF THE SAME NAME, AND THE HALF THAT
> REACHES THE POD.** … So the chart names the image by DIGEST, which cannot
> move, and THIS COMPOSER is the party that knows both ends: it takes the
> image job's build output and hands it to the chart job, which writes it into
> `values.yaml`'s `image.digest` before `helm push`. … The tag stays as well:
> it is the human-readable half of the name, every service chart keeps
> `image.tag` equal to `appVersion` (the publish seam asserts it), and
> `bin/chart-test` renders it beside the digest.
>
> `image-digest: ${{ needs.image.outputs.digest }}` — "Derived, never typed …
> Empty when nothing was pushed: the chart then packages as committed."

## 2. The workflows, verified (no finding)

- `.github/workflows/publish.yml` (lines 57–61) calls the composer already:
  `uses: cafaye/kit/.github/workflows/publish.reusable.yml@master` with
  `push: true`, and grants `packages: write` at line 51 (the caller's to
  grant — the caller has it). So the digest hand-off reaches this repository
  on every push to master. **No change needed, none made.**
- No other file in `.github/workflows/` names the service image. `ci.yml`'s
  `image:` references are its own `postgres:17-alpine` service container
  (deliberately pinned by tag, not digest — the comment at lines 183–187
  explains the cross-platform reason), and `MODULE: github.com/cafaye/identity`
  is the Go module path. The push caller's own contract is guarded in-tree by
  `internal/platform/ci/publish_test.go`, which this packet did not touch and
  which stays green.

## 3. The change

**The template** (`chart/templates/deployment.yaml`) — the image line becomes
a conditional, and the only other template that named the image was this one
(`grep -rn repository chart/templates/` returns exactly one hit, line 33):

```
          {{- if .Values.image.digest }}
          {{- if not (regexMatch `^sha256:[0-9a-f]{64}$` .Values.image.digest) }}
          {{- fail (printf "chart: image.digest is %q, not sha256:<64 hex>. …" .Values.image.digest) }}
          {{- end }}
          image: "{{ .Values.image.repository }}@{{ .Values.image.digest }}"
          {{- else }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          {{- end }}
```

**The committed digest** (`chart/values.yaml`) — the value from the registry,
verbatim, with the comment above it saying what writes it (the publish
workflow, from the image job's build output, before `helm package`), why it
exists (the measured tag defect: a mutable tag rendered an identical
Deployment after every build, Argo reported `Synced`, `IfNotPresent`
re-served the stale copy), and that the committed value is what a fresh clone
renders:

```
  digest: "sha256:e2a064627b6b5a7f1165c3ef1ec8753958b9810fb92b2a3aea1326990592174d"
```

**The tests** (`internal/chart/render_test.go`, plus a subtest rewrite in
`chart_test.go`) — see §4.

`internal/chart/chart.go`'s reader split into `parseFile`/`parseBytes` so the
same refusing reader that reads the chart off disk can read a rendered
document out of memory. `Chart.yaml`, `appVersion`, the app, the other values
and both workflows are untouched.

## 4. The template-side decision on a malformed digest: REFUSE, not absent

The brief's question was whether the template treats a digest that is not
`sha256:<64 hex>` as absent (render `repository:tag`) or refuses. **It
refuses**, and the template's own error message says why. A template cannot
stop the write the way kit's step refuses it before the write — the value is
already in `values.yaml` — so its only choices are what the render does with
it. Three reasons for refusing:

1. **Absence re-creates the measured defect, silently.** A hand-edited
   `digest: sha256:tooshort` would fall back to the tag, and the chart would
   render `repository:0.1.0` from then on: a mutable reference, no textual
   diff on a new build, Argo reporting `Synced` and rolling nothing. The
   values file would READ as pinned while the box ran whatever the tag last
   held. That is the six-hour stale deployment, re-created under a value that
   looks like a pin. The failure direction matters: this repository's rule in
   every other packet is that the safe direction is the loud one.
2. **`repository@nonsense` is barred** — that is the third option and it is
   what kit's step exists to prevent ("looks like a pin and fails at
   image-pull with nothing naming this step").
3. **A malformed digest can only arrive by human hand-edit** — the workflow
   refuses it at the write, so the refusal is a message to the person who
   typed it, delivered at the moment Argo diffs, naming the field and the
   value. And the failure is recoverable: Argo keeps its last good render, the
   sync goes red, and the chart is not deployed.

Empty is the fourth and separate state, and it is NOT a refusal: with no
digest at all the Deployment renders `repository:tag`, which is what a fresh
clone, a `push: false` run and a direct caller of the chart workflow all
package — and what this repo rendered for its whole life before the field
existed. A digest that is present and WRONG is not the supported absence.

## 5. The proofs

### 5.1 Both renders, asserted by the chart tests (in the gate)

`internal/chart/render_test.go` evaluates the Deployment template with
`text/template` — Helm's own engine — over the three functions the chart
uses (`quote`, `regexMatch`, `fail`; anything else errors as
`function "..." not defined`, so the evaluator cannot silently
under-render). It is not a second Helm and the file says so. Four render
tests, all in `internal/chart`, which `bin/prime` runs:

| test | what it proves |
| --- | --- |
| `TestTheDeploymentRendersTheImageByDigestWhenValuesCarryOne` | the committed digest is present and is the registry's grammar; the committed values render `repository@digest`; a CHANGED digest changes the rendered image (the property Argo's diff reads); no digest renders `repository:tag`, exactly as before; a changed repository renders beside the digest |
| `TestTheImageDigestIsRefusedRatherThanRendered` | seven malformed digests each fail the render, the output is empty, and the error names the field and the value |
| `TestTheCommittedDigestIsWhatAFreshCloneRenders` | a clone with no publish behind it renders the pin, and the rendered string is `repository@` plus 64 hex |

`chart_test.go`'s image-line subtest moved onto the raw template text. The
reason is worth recording: the file reader SKIPS Helm action lines, so
navigating to `containers[0].image` sees only the LAST branch it parsed — the
tag path — while the digest path sits in the skipped lines. A test written the
old way would have passed on a template with the digest branch deleted, which
is the measured defect in miniature. That blind spot is why the render proof
exists at all.

### 5.2 The real helm, on the pinned version

`helm` v4.3.0 (the fleet's pin, and the version kit's own step installs) is
on this machine, so the renders were checked against the real engine as well:

```
$ helm template identity chart/ | grep 'image:'
          image: "ghcr.io/cafaye/identity@sha256:e2a064627b6b5a7f1165c3ef1ec8753958b9810fb92b2a3aea1326990592174d"
$ helm template identity chart/ --set image.digest="" | grep 'image:'
          image: "ghcr.io/cafaye/identity:0.1.0"
$ helm template identity chart/ --set image.digest=null | grep 'image:'
          image: "ghcr.io/cafaye/identity:0.1.0"
$ helm template identity chart/ --set image.digest="sha256:abc"; echo "exit: $?"
Error: execution error at (identity/templates/deployment.yaml:46:14): chart:
image.digest is "sha256:abc", not sha256:<64 hex>. The registry's manifest
digest is the only shape a pin can take: …
exit: 1
$ helm lint chart/
1 chart(s) linted, 0 chart(s) failed
```

The refusal reaches Argo the same way: a chart whose render fails syncs red
rather than deploying a wrong image.

### 5.3 The three red proofs

A check that has never been observed red is a claim about a check nobody
tested. `bin/red-proofs` (untracked instrument, kept in the worktree for a
successor to rerun) breaks one thing at a time, restores after each:

**red-1 — the committed digest blanked** (`digest: ""` in values.yaml):

```
--- FAIL: TestTheDeploymentRendersTheImageByDigestWhenValuesCarryOne
    --- FAIL: .../the_committed_digest_is_present_and_is_the_registry's_grammar
    --- FAIL: .../the_committed_values_render_repository@digest
    --- FAIL: .../a_fresh_digest_changes_the_rendered_image,_which_is_the_diff_Argo_reads
--- FAIL: TestTheCommittedDigestIsWhatAFreshCloneRenders
exit 1
```

**red-2 — the digest branch deleted from the template** (what this repo
shipped for its whole life, and what the other six un-adopted repos still
ship):

```
--- FAIL: TestTheDeploymentServesThePortTheDockerfileExposesAndReadyz
    --- FAIL: .../the_image_is_named_from_values,_by_digest_when_there_is_one
--- FAIL: TestTheDeploymentRendersTheImageByDigestWhenValuesCarryOne
    --- FAIL: .../the_committed_values_render_repository@digest
    --- FAIL: .../a_fresh_digest_changes_the_rendered_image,_which_is_the_diff_Argo_reads
    --- FAIL: .../no_digest_renders_repository:tag,_exactly_as_before
    --- FAIL: .../a_changed_repository_renders_beside_the_digest
--- FAIL: TestTheImageDigestIsRefusedRatherThanRendered
exit 1
```

**red-3 — the malformed-digest refusal deleted** (a template that still
renders both well-formed branches but no longer rejects a bad one):

```
--- FAIL: TestTheDeploymentServesThePortTheDockerfileExposesAndReadyz
    --- FAIL: .../the_image_is_named_from_values,_by_digest_when_there_is_one
--- FAIL: TestTheImageDigestIsRefusedRatherThanRendered
    --- FAIL: .../not-a-digest
    --- FAIL: .../sha256:
    --- FAIL: .../sha256:aaaaaaaa…aaa (63)
    --- FAIL: .../sha256:aaaaaaaa…aaa (65)
    --- FAIL: .../sha256:AAAAAAAA…AAA (uppercase)
    ... (seven cases)
exit 1
```

After each restore, `git status` is clean and the package is green again.

## 6. The gate

The gate for this repository is `bin/prime` (Go), which needs a PostgreSQL
with the migrations applied. The shared cluster's `identity` database held a
stale goose state (`relation "users" already exists` from a previous
provision), so the gate ran against a fresh `identity_adopt` database that
`bin/provision-testdb` created and migrated, over the host-mapped port 15500
(the machine's 5432 is not the compose cluster's):

```
TEST_DATABASE_URL=postgres://identity:cafaye@localhost:15500/identity_adopt?sslmode=disable
TEST_DATABASE_ADMIN_URL=postgres://cafaye:cafaye@localhost:15500/postgres?sslmode=disable
mise exec -- ./bin/prime
```

**GREEN: exit 0, 32 `ok` package lines, 0 `FAIL`, 0 `SKIP`.**
`ok github.com/cafaye/identity/internal/chart 0.980s` is in that set — the
render tests run inside the gate, not beside it. The provisioned database is
left in place (the gate is idempotent), and no file in the tree changed after
the run: `git status` is clean and the branch carries the packet's commit and
nothing else.

`gofmt -l .` prints nothing; `go vet ./internal/chart/` is clean.

## 7. What I deliberately did NOT do

- **Did not touch `Chart.yaml`**, `appVersion`, the app, or any other chart
  value. `image.tag` stays `"0.1.0"`, equal to `appVersion` — the tag is the
  human-readable half of the name and the composer's own seam keeps them
  equal.
- **Did not change either workflow.** The publish caller already composes;
  the contract's verification is §2.
- **Did not add a `bin/chart-test`.** Gateway (a Node repo, whose gate cannot
  run Go) keeps its helm render outside the gate as a bounded command; this
  repository's gate IS a Go gate, so the render proof belongs in
  `internal/chart` and runs inside it. The real helm render in §5.2 is the
  operator-side check, recorded here rather than committed as a second place
  to maintain.
- **Did not fix `gate.yml`'s stale prose** (`suite: 1989 PASS`, `18 packages`
  — the tree is 32 packages and ci.yml's floor is 3442). Pre-existing drift
  from earlier packets, out of scope for a chart change, and touching it would
  be an unmeasured claim.
- **Did not touch kit or any other repository**, and spawned no agent.

## 8. Commits

```
2ff895f chart: render the image by digest when values carry one
7418399 docs: record the digest-pin adoption, the renders and the red proofs
```

The acceptance test is the manager's: push a trivial change, the composer
republishes the chart with the fresh digest, and Argo rolls the Deployment
with no human step. The chart-side proof is §5 and the green gate.

**One open item, recorded rather than guessed:** `SUITE_FLOOR` in
`.github/workflows/ci.yml` is 3442, measured on the tree before this packet's
tests. This packet's tree measures 3453 PASS lines; raising the floor needs a
GREEN `-v -race` count, and the first such run failed in `internal/migrate`
for an environmental reason (scratch databases dropped under the cluster's
30-second statement timeout, at the default parallelism the counting step
does not use). The floor is a minimum and still holds; a re-measured run at
`-p 1` — the serialisation ci.yml's own floor comment prescribes — was started
and had not finished when the packet's hour closed. The successor's first move
is in §9.

## 9. The successor's first move

1. Read `/tmp/count-serial-adopt-digest-identity.log` (or re-run
   `go test -v -count=1 -race -p 1 ./...` against `identity_adopt` — the
   provisioned database from §6 is still there). If it is green and counts
   3453 PASS / 4 SKIP (the four declared courier e2e exemptions), raise
   `SUITE_FLOOR` to that number in `.github/workflows/ci.yml` in one commit
   that quotes the run. **Do not touch `DATABASE_TIER_FLOOR`** — this packet's
   tests are in a fast-tier package and the tier count does not move.
2. `./bin/red-proofs /tmp/<fresh-dir>` reruns the three red proofs (§5.3) if
   the template is ever edited again.
3. The caf-side packet that makes `caf gen chart` EMIT the digest branch is
   still open; until it lands, a `caf gen chart -force` would drop this
   adoption, which is why the template comment names it.
