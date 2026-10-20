// Checks on ci/publish.yml — the workflow that builds and pushes
// the two artifacts a deploy consumes: the image `config/deploy.yml` deploys
// and the chart the Argo CD `Application` pulls.
//
// WHY A SEPARATE FILE. The tests in ci_test.go all read `ci.yml`, which is the
// workflow that proves the tree. This one reads a different file that proves
// something else: that the artifacts a deploy pulls are produced by a pipeline
// rather than by one person on one machine. Splitting them keeps each file's
// header honest about which file it is talking about, and it means a change to
// one workflow does not have to be reasoned about through the other's tests.
//
// # What these deliberately do not do
//
// They do not parse the workflow as YAML. ci_test.go's header says why and the
// reason holds here: a dependency with no stated cause, and a line scan is
// enough for a file whose shape this repository controls.
//
// # Why these checks exist at all
//
// Every one of them is a claim that fails SILENTLY when it stops being true.
// The file is not run on a pull request, so a mistake in it cannot be caught by
// the mistake being noticed — it can only be caught by a check, or by a deploy
// failing to find an image, or by an Application syncing a chart tag that
// nothing ever wrote. The last failure is the one this packet exists for:
// identity's chart landed (identity-w89) while this caller still named kit's
// IMAGE workflow, so the chart the substrate pulls at `targetRevision: 0.1.0`
// was published by no pipeline at all, and nothing was red.
package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// kitPublishWorkflow is the composition, called rather than copied: one `uses:`
// that publishes the image AND the chart. Written out in full for the same
// reason `kitWorkflow` is: the value of comparing it is that a reader can
// check it against kit's tree with one `ls`.
//
// The name is the assertion. `image.reusable.yml` is what this file used to
// require, and it is the exact regression this packet prevents: it builds and
// pushes the image and says nothing about a chart, so a check that accepted any
// `cafaye/kit` `uses:` would pass on a tree whose chart is published by
// nothing.
const kitPublishWorkflow = "cafaye/kit/ci/publish.reusable.yml@master"

// defaultChartDir is the `chart-dir` input's default in kit's publish and chart
// reusable workflows. Resolved here rather than assumed: the caller names no
// `chart-dir`, so the default is where the workflow reads Chart.yaml from, and
// a default that drifted from kit's would be a second place to be wrong about
// the same fact.
const defaultChartDir = "chart/"

// substrateTargetRevision is the tag the substrate's Argo CD `Application`
// pins for this chart. The chart's Chart.yaml `version` IS the OCI tag —
// chart.reusable.yml reads name and version from Chart.yaml and never takes
// them as inputs — so the two are one fact written twice, and a service that
// bumps one and not the other is a service that never deploys.
const substrateTargetRevision = "0.1.0"

// publishWorkflow is the file, relative to the repository root.
const publishWorkflow = "ci/publish.yml"

var (
	// Any `uses:` pointing at kit, at any indentation. Used to prove the file
	// calls kit and does not also carry a build of its own.
	kitUseLine = regexp.MustCompile(`^\s+uses:\s+(cafaye/kit/\S+)\s*$`)
	// `packages: write`, at any indentation, and nothing after it on the line.
	// Anchored both ends so `packages: write-foo` cannot satisfy it.
	packagesWrite = regexp.MustCompile(`(?m)^\s*packages:\s*write\s*$`)
	// A `pull_request:` trigger. This is deliberately read from the raw file
	// rather than from comment-stripped lines, because it is a `on:` key and
	// nothing else in this file can produce one.
	pullRequestTrigger = regexp.MustCompile(`(?m)^\s*pull_request:`)
	// A `chart-dir:` input at any indentation, capturing the directory. Only
	// the caller's `with:` block can carry one and this file's shape is
	// controlled here, so a line scan is enough.
	chartDirInput = regexp.MustCompile(`(?m)^\s*chart-dir:\s*(\S+)\s*$`)
	// A `version:` line in Chart.yaml, capturing the value. A line scan rather
	// than a YAML parse for the reason this file's header gives: go.mod has
	// no YAML dependency and this repository controls Chart.yaml's shape.
	// `appVersion:` does not match — the anchor is the line start.
	chartVersionLine = regexp.MustCompile(`(?m)^version:\s*(\S+)\s*$`)
)

func publishLines(t *testing.T) []string {
	t.Helper()

	path := filepath.Join(repoRoot(t), publishWorkflow)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s could not be read, and nothing else in this repository publishes the image config/deploy.yml deploys or the chart the Application pulls: %v",
			publishWorkflow, err)
	}
	return strings.Split(string(raw), "\n")
}

// TestTheArtifactsAreBuiltBySomethingThatRuns. The gap this closes:
// `config/deploy.yml` names ghcr.io/<org>/<repo> and `kamal deploy` pulls it,
// and the substrate's Application pulls oci://ghcr.io/cafaye/charts/identity —
// with no publisher, the only way either artifact existed was one person running
// `docker build` and `helm package` on one machine. CI stayed green the entire
// time — a green CI and an unpublished artifact are not in tension, they are
// just both true, which is what makes the gap easy to miss.
func TestTheArtifactsAreBuiltBySomethingThatRuns(t *testing.T) {
	// The t.Fatalf inside publishLines carries the whole explanation; this
	// exists so the failure reads as a claim that lost, not as a helper.
	publishLines(t)
}

// TestThePublishWorkflowCallsKitsComposedPublishAtAPathThatResolves. The second
// half of `kitWorkflow`'s rule, applied to the second call. GitHub resolves a
// cross-repository reusable workflow at
// {owner}/{repo}/ci/{file}@{ref} and documents that
// subdirectories of the workflows directory are NOT supported, so any other path
// resolves to nothing and the job is red before it starts.
//
// Exactly one kit call is required, and it must be the COMPOSED one. A second
// call is a repository where somebody copied the wrong line; an image-only
// call is the regression this packet exists to prevent — it publishes the
// image and nothing else, so the chart the Application pulls is published by
// no pipeline, and nothing is red until a deploy syncs a tag that does not
// exist.
func TestThePublishWorkflowCallsKitsComposedPublishAtAPathThatResolves(t *testing.T) {
	var calls []string
	for _, line := range publishLines(t) {
		if m := kitUseLine.FindStringSubmatch(line); m != nil {
			calls = append(calls, m[1])
		}
	}

	switch len(calls) {
	case 0:
		t.Fatalf("%s calls nothing from kit; the publish path is supposed to be the composed one at %s",
			publishWorkflow, kitPublishWorkflow)
	case 1:
	default:
		t.Fatalf("exactly one call to kit's publish workflow belongs in %s, and %d do: %v",
			publishWorkflow, len(calls), calls)
	}
	if calls[0] != kitPublishWorkflow {
		t.Fatalf("the call is %q, want %q.\n"+
			"GitHub resolves a cross-repository reusable workflow at\n"+
			"  {owner}/{repo}/ci/{file}@{ref}\n"+
			"and documents that subdirectories of the workflows directory are NOT\n"+
			"supported, so any other path resolves to nothing and the job is red\n"+
			"before it starts.\n\n"+
			"The name is the assertion. cafaye/kit/ci/image.reusable.yml\n"+
			"is the caller this file used to require: it builds and pushes the image\n"+
			"and says nothing about a chart, so identity's chart — which the\n"+
			"substrate's Application pulls at targetRevision %s — was published by\n"+
			"nothing. The composed workflow is the one that publishes both.",
			calls[0], kitPublishWorkflow, substrateTargetRevision)
	}
}

// TestThePublishWorkflowDoesNotCarryItsOwnBuild. The reason this file calls kit
// instead of copying the build is that a copy is a second pipeline: six
// repositories with six copies is six places for a security fix to land in five,
// and the first one to drift is the one nobody remembers. The same holds for
// the chart: the composition itself is not a thing to copy, it is the file the
// one `uses:` names.
func TestThePublishWorkflowDoesNotCarryItsOwnBuild(t *testing.T) {
	for i, line := range publishLines(t) {
		if !strings.Contains(line, "docker/build-push-action@") {
			continue
		}
		// A comment is allowed to say the words — this file's own header does.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		t.Errorf("%s:%d carries its own build step:\n\t%s\n"+
			"The build belongs to kit, shared, so a fix to how an image is built reaches\n"+
			"this repository on kit's next push. Naming the action in a comment is fine;\n"+
			"depending on it here is the thing being prevented.",
			publishWorkflow, i+1, strings.TrimSpace(line))
	}
}

// TestThePublishWorkflowGrantsPackagesWrite. A reusable workflow can REQUEST a
// permission but cannot grant itself one, so this line is the caller's job and
// there is no way to get it from the other repository.
//
// The failure mode is why this is checked: without it the push fails with a 401,
// which reads like a wrong password rather than like the missing line it is.
func TestThePublishWorkflowGrantsPackagesWrite(t *testing.T) {
	if !packagesWrite.MatchString(strings.Join(publishLines(t), "\n")) {
		t.Errorf("%s does not grant `packages: write`.\n"+
			"A reusable workflow can request a permission but cannot grant itself one, so\n"+
			"this line is the caller's job. Without it the push fails with a 401 at run\n"+
			"time, which reads like a bad password rather than like the missing line.",
			publishWorkflow)
	}
}

// TestThePublishWorkflowIsNotTriggeredByPullRequest. Two reasons and both are
// real: only master holds deployable commits, so a branch build publishes images
// nobody deploys; and a pull request build runs untrusted code — the Dockerfile,
// whatever a contributor changed — against a registry write.
//
// The reusable workflow refuses to publish on a pull request regardless of what
// the caller asks, so this is belt and braces. It is here because a reader of
// this file should be able to see the guard without reading another repository.
func TestThePublishWorkflowIsNotTriggeredByPullRequest(t *testing.T) {
	if pullRequestTrigger.MatchString(strings.Join(publishLines(t), "\n")) {
		t.Errorf("%s is triggered by `pull_request`.\n"+
			"A pull request build would run a contributor's Dockerfile against a\n"+
			"registry write, and publish images for commits nobody can deploy.",
			publishWorkflow)
	}
}

// TestThePublishWorkflowAsksToPush. `push` defaults to FALSE in kit's reusable
// workflows, deliberately: calling a build and publishing one are two different
// acts, and a default of true would mean every caller that only wanted to check
// the artifacts still wrote to the registry. So this repository's caller has to
// say so out loud, and a caller that stops saying it goes back to building and
// packaging without publishing — which fails silently, and looks exactly like
// a slow CI run. The composed workflow threads the one `push` input to both the
// image and the chart, so this single line is what publishes both artifacts.
func TestThePublishWorkflowAsksToPush(t *testing.T) {
	for _, line := range publishLines(t) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "push: true" {
			return
		}
	}
	t.Errorf("%s never asks to publish.\n"+
		"`push` defaults to false in kit's publish workflow, so a caller that does not\n"+
		"say `push: true` builds the image and packages the chart and pushes neither.\n"+
		"That failure is silent: the job is green, the artifacts are written locally,\n"+
		"and the registry has nothing — the deploy fails later, at a tag that does\n"+
		"not exist.",
		publishWorkflow)
}

// TestTheChartVersionIsTheTagTheSubstratePulls. The chart half of the publish
// loop, and the seam that decides whether a deploy finds the artifact at all:
// chart.reusable.yml reads the chart's name and version from Chart.yaml and
// never takes them as inputs, pushes to oci://ghcr.io/cafaye/charts, and tags
// the chart with its `version`. The substrate's Application pulls
// `targetRevision: 0.1.0`. The chart's version and the Application's
// targetRevision are therefore one fact written twice, and a service that
// bumps one and not the other never deploys — Argo reports no error, it just
// never finds the artifact.
//
// The chart dir is RESOLVED from the caller's `chart-dir` input, defaulting to
// the input's default, rather than assumed: a caller that names its chart
// somewhere else is read, not overridden.
func TestTheChartVersionIsTheTagTheSubstratePulls(t *testing.T) {
	chartDir := defaultChartDir
	if m := chartDirInput.FindStringSubmatch(strings.Join(publishLines(t), "\n")); m != nil {
		chartDir = m[1]
	}

	chartYAML := filepath.Join(repoRoot(t), chartDir, "Chart.yaml")
	raw, err := os.ReadFile(chartYAML)
	if err != nil {
		t.Fatalf("the caller's chart dir %s holds no Chart.yaml (%v).\n"+
			"Chart.yaml is where the chart's name and version live — chart.reusable.yml\n"+
			"reads them from that file and never takes them as inputs, so a chart\n"+
			"dir that does not hold one is a chart nothing can publish.",
			chartDir, err)
	}

	m := chartVersionLine.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("%s carries no `version:` line, and the version is the OCI tag the chart is pushed under",
			chartYAML)
	}
	if m[1] != substrateTargetRevision {
		t.Errorf("Chart.yaml version is %s, but the substrate's Application pins targetRevision %s.\n"+
			"The chart's version IS the OCI tag: chart.reusable.yml reads name and\n"+
			"version from Chart.yaml and never takes them as inputs, so a chart\n"+
			"pushed as %s while the Application pulls %s is a service that never\n"+
			"deploys — Argo reports no error, it just never finds the artifact.",
			m[1], substrateTargetRevision, m[1], substrateTargetRevision)
	}
}
