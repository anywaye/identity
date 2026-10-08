# REPORT-m122b — identity security-test tree walk under a symlinked checkout

Packet m122b. Fix + verification only: one helper changed, one regression test
added, both in `internal/platform/ci/ci_test.go`. The workflow's 77-name
security list is untouched and the assertion is not weakened.

## Root cause

`repoRoot` derived the repository root from `runtime.Caller(0)`'s file path
without resolving symlinks. This checkout is reached through a symlink
(`/Users/kaka/Code/any/wt/identity` -> `.../moon/cafaye/identity`), so the
embedded path — and therefore `repoRoot` — carried the symlinked prefix.

Every other helper in the file kept passing because a direct read
(`os.ReadFile`) follows symlinks without complaint. Only `testNamesInTree`
walks, and `filepath.WalkDir` never follows a symlink, not even the root
itself: `Lstat` on the symlinked root reports a non-directory, so the walk
visited exactly one entry and stopped, returning an empty map. The guard then
reported all 77 named tests missing while static grep found every one of them
— the m117 finding, reproduced here standalone with no DB.

Proved, not guessed: a temporary diagnostic test logged
`repoRoot="/Users/kaka/Code/any/wt/identity"`, stat OK, and
`dirs=0 testFiles=0 other=1` from the walk (diagnostic removed afterwards).
Note: the m117 report says "80 names"; the workflow step
(`ci.yml:721-797`) lists 77, and the failure output held 77 errors — the
manifest contract itself is unchanged by this packet either way.

## Fix

`repoRoot` now returns `filepath.EvalSymlinks(root)` (fatal on error: a root
that cannot be resolved is a failure, not a skip). No nested symlinks exist in
the tree (`find . -type l` empty outside `.git`), so resolving the root fully
restores the walk. Direct-read helpers resolve to the same files as before.

## Regression coverage

`TestTheTreeWalkSeesThroughACheckoutSymlink` asserts both the defect and its
symptom: `repoRoot` carries no symlink, and the walk finds a witness test
defined in its own package (`TestTheNamedSecurityTestsExist`). Verified it
fires on unfixed code (both assertions red: root still symlinked, walk finds
nothing) and passes with the fix.

## Focused test result

`timeout 300 go test ./internal/platform/ci -run
'TestTheNamedSecurityTests(Exist|AreEnough)$' -count=1` → both PASS
(`TestTheNamedSecurityTestsExist`, `TestTheNamedSecurityTestsAreEnough`).
`gofmt -l internal/platform/ci/` prints nothing; `go vet
./internal/platform/ci/` clean. No DB, container, full gate, or stack
operation performed.
