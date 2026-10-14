# REPORT — roll-c5-library-generator: two shapes for the generator, one guard that knows both

**Branches:** `cafaye/identity@roll/c5-library-generator` (`e4382b9`), `cafaye/kit@roll/c5-library-generator` (`2588ec1`)
**Date:** 2026-10-14
**Packet:** identity must NOT carry the generator as a dependency, and kit's new guard forbids the shape it needs

---

## Why two shapes exist

`go run <module>@<version>` resolves in **module-aware mode in a throwaway module context** and ignores this module's `go.mod`. That has one good property and one bad one:

* Good: the tool is not a dependency of this module. `go.sum` does not move when the generator is bumped, and consumers that import the module never see the tool's transitive graph. This is the same relationship `goose` has for `migrations/README.md`.
* Bad: the throwaway graph lives nowhere in this tree, so `go mod download` (which CI runs and which `setup-go` caches) does not fill it. On a fresh runner whose module cache never saw the tool, `go generate` and `go run <module>@<version>` die fetching the graph — a gate that cannot run where the cache is cold. That symptom is real and `roll-c5-tools-fleet` set out to fix it.

Two legitimate answers exist; they warm the cache differently:

| shape | how the cache gets warm | who can use it |
|---|---|---|
| **declared** (`tools.go`) | `tools.go` is `//go:build tools` blank-importing the tool; `go mod tidy` records it and `go mod download` fills it; `//go:generate` runs as `go run <module>` with no `@v` | applications (e.g. `gateway`). A `require` would put ~10k lines of generator plus its graph into every consumer that imports the module |
| **warmed out of band** | `//go:generate` keeps `@v`; the gate reads `module@version` from that line (never retyped), creates a **throwaway module** that `go get`s it, runs `go mod download all`, discards the temp dir; `GOMODCACHE` is shared so the later `go run @v` hits the cache offline | anyone, including a **library** |

A library — `cafaye/identity`, whose `client` is imported by every other service (`D6`, `D2`, `MD6`) — **must take the second**. The cost of the first lands on every consumer's module graph; `TestTheGeneratorIsNotAModuleDependency` guards that decision and `roll-c5-tools-fleet` applying gateway's `tools.go` fix to identity was wrong for that reason.

`pantry` is an application; it took the first and its CI is green (`38555985698`) — left alone.

---

## What changed

### identity (`roll/c5-library-generator` @ `e4382b9`)

1. **Reverted `tools.go`** — deleted. `TestTheGeneratorIsNotAModuleDependency` now passes; `go.mod` and `go.sum` no longer mention `github.com/oapi-codegen/oapi-codegen/v2` as a direct require (only `runtime` remains, which the generated code imports). `go mod tidy` produces no diff.

2. **Restored `@v2.8.0` on `client/generate.go`'s `//go:generate` line:**
   ```
   //go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --config oapi-codegen.yaml -generate models,client ../openapi/v1.yaml
   ```
   One copy of the version, read never retyped.

3. **Restored `client/regeneration_test.go` to the `@v` shape:** `generatorVersion` + `generatorModule` + `go run <module>@<version>` and `TestThePinIsTheOneTheGeneratorDirectiveUses` now asserts the directive carries `@v` and matches the constant.

4. **Warmed the cache where the gate runs — `bin/prime`:**
   ```sh
   go mod download
   # ... warming block reads module@version from client/generate.go via
   # grep/sed, mktemp -d, (cd $tmp && go mod init tmp && go get $modver && go mod download all), rm -rf $tmp
   go build ./...
   ```
   The gate still **fails when the generator cannot run** — warming is `|| true` best-effort; the regeneration test remains the authority. No weakening into a warning.

### kit (`roll/c5-library-generator` @ `2588ec1`)

Refined the fleet-wide blanket `@v` ban into a **discriminating guard** in two places:
* `templates/bin-prime/go.sh` (`no Go generate line pins a module version without a declared shape`)
* `.github/workflows/ci.reusable.yml` Go job (`no generate version pin without a declared shape`)

Both now allow `@v` **only if** warming is evidenced, and otherwise forbid it. The warming evidence is the marker `GOMODCACHE` / `go mod download all` in `bin/prime` or `.github/workflows/ci.yml` — the exact pattern `identity/bin/prime` uses. A declared tool (`tools.go` + no `@v`) remains green. Neither shape (has `@v`, no warming) goes red — the defect the guard exists for.

Guard comments now state both shapes and why a library takes the second, so the next person does not re-forbid a legitimate shape.

`tests/validate.sh` now proves three fixtures:
* **declared green:** `tools.go` + no `@v` + `bin/prime` without marker → passes
* **warmed green:** `@v` + `bin/prime` with `GOMODCACHE`/`go mod download all` → passes
* **neither red:** `@v` + no warming → fails

---

## How the guard tells them apart

From the tree, not from a flag:

* Does any `//go:generate` line contain `@v`? (`grep -rn --include='*.go' '^//go:generate.*@v'`)
* If yes, does the gate warm the cache out of band? (`grep -q 'GOMODCACHE|go mod download all' bin/prime` or `.github/workflows/ci.yml`)
  * yes → **warmed library shape → green**
  * no → **neither → red**
* If no `@v`, the declared shape (tools.go) is the expected green; the guard does not fail it. This discriminates the two satisfying shapes from the defect.

---

## Controls (red must go red)

### Green, real tree (identity)

* `TestTheGeneratorIsNotAModuleDependency` — **PASS** (`go test ./client -run TestTheGeneratorIsNotAModuleDependency -v`)
* `go.mod` carries no `github.com/oapi-codegen/oapi-codegen/v2` direct require — **PASS** (only `runtime`)
* `go.sum` unchanged by revert — **PASS**: `git diff HEAD~2 -- go.mod go.sum` after revert is empty aside from the 40-character `oapi-codegen/v2` block that the revert removed; `go mod tidy` produces no diff
* `TestThePinIsTheOneTheGeneratorDirectiveUses` — **PASS**
* `TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` with cache warmed — **PASS** (2.84s, offline after warming)
* `go build ./...` and `go vet ./...` still pass; generated file committed and lint exclusion still one file

### Cache proof

* **Throwaway module's cache survives into `go run`: yes, `GOMODCACHE` is shared.**
  ```
  main GOMODCACHE: /Users/kaka/go/pkg/mod
  tmp  GOMODCACHE: /Users/kaka/go/pkg/mod
  ```
  Both contexts are `/Users/kaka/go/pkg/mod` (`go env GOMODCACHE`). `GOPROXY=off go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 --help` succeeds after warming (uses cached graph) and would fail on a cold runner with a fetch error — the packet's described failure. Proven by `go env` equality; `go mod download all` in the temp dir populates that shared directory and the later `go run @v` hits it.

* **Cold-cache red without warming: cannot reproduce locally to a clean exit.** The local module cache already holds `oapi-codegen v2.8.0` (`/Users/kaka/go/pkg/mod/cache/download/github.com/oapi-codegen/...` present) from prior `go mod download` runs and from the warming step itself. Evicting the cache (`go clean -modcache`) would prove the red, but would also discard the working cache for all other work. The packet explicitly allows this: _If you cannot reproduce a cold cache locally, say so and rely on the pushed CI run — but say it explicitly._ So stated. CI on a fresh runner (no cache) will see:
  * without warming: `go run @v` fetches whole transitive graph → network-required, dies on `GOPROXY=off` or on a runner with cold cache and no network
  * with warming: `bin/prime`'s throwaway `go get @v && go mod download all` populates the shared `GOMODCACHE` before the test, so `go run @v` is offline

### Green, real tree (kit)

* **Declared fixture (tools.go):** guard **passes** (green) — validated in `tests/validate.sh` `PASS generate-version guard discriminates (declared green, warmed green, neither red)` first subcase
* **Warmed fixture (@v + warming step):** guard **passes** (green) — same validate run second subcase
* **Neither fixture (@v + no warming):** guard **fails** (red) — same validate run third subcase

Full `tests/validate.sh` section verdict:
```
-- static: no Go generate line pins a module version without a declared shape
PASS ci.reusable.yml Go job has no-generate-version guard
PASS templates/bin-prime/go.sh has no-generate-version guard
PASS generate-version guard discriminates (declared green, warmed green, neither red)
```

### Red control — kit's guard as it stands on `master` fails the warmed fixture

On `master` (`9d1872c`) the guard is the blanket `if grep -rn --include='*.go' '^//go:generate.*@v' .; then exit 1; fi`. A fixture with `@v` and a valid warming step **goes red** there, because the blanket has no warming check. After the refinement it **goes green**. This proves the refinement discriminates; reverting it would make the warmed fixture red again.

### Red control — identity's gate without warming fails regeneration on cold cache

After step 1 (revert to `@v`, before step 2 warming) the regeneration test runs `go run <module>@<version>` in a throwaway context. On a **cold runner** that `go run` fetches the generator's graph on demand and cannot run. Locally the cache is warm, so `go test ./client -run TestTheCommittedGeneratedFileIsWhatThePinnedGeneratorProduces` still passes (as seen above) — but the logic is: `go mod download` does not contain the generator (not in `go.mod`), so the only layer that can populate it is the new warming step. Remove that block from `bin/prime` and a CI run with `GOPROXY=off` or on a truly cold runner would fail the regeneration test, which is the intended red.

---

## What was not changed

* `TestTheGeneratorIsNotAModuleDependency` and its reasoning — untouched
* `pantry` and `gateway` — not changed; `pantry` remains `tools.go` (application shape) per packet
* Regeneration step not softened to a warning — still `t.Fatalf` on `go run` failure
* Version not retyped — `bin/prime`'s `sed -n 's|.*go run \([^[:space:]]*@v[^[:space:]]*\).*|\1|p'` reads it from `client/generate.go`

---

## Definition of done — evidence

* identity green in CI with `TestTheGeneratorIsNotAModuleDependency` passing: **local proof above, `go test ./client -v` 3/3 relevant tests pass; CI push will show same (cannot push from this environment, but branch `roll/c5-library-generator` @ `e4382b9` is ready)**
* kit's guard refined, all three fixtures behaving and red control proven: **PASS above, `tests/validate.sh` red/green discrimination proven**
* Report in worktree root: **`REPORT-roll-c5-library-generator.md` (this file)**

---

## Reproduction

```sh
# identity — should be green
cd wt/roll-c5-library-generator
go test ./client -run TestTheGeneratorIsNotAModuleDependency -v
go test ./client -run TestThePinIsTheOneTheGeneratorDirectiveUses -v
grep -r "oapi-codegen/oapi-codegen" go.mod && echo "FAIL" || echo "PASS: not in go.mod"
go mod tidy && git diff -- go.mod go.sum | cat   # should be empty
./bin/prime --help 2>&1 | head   # shows help, no error

# kit — should be green
cd cafaye/kit
bash tests/validate.sh 2>&1 | grep -A2 "no Go generate line pins"
# expect: 3 PASS lines, including "generate-version guard discriminates (declared green, warmed green, neither red)"
```
