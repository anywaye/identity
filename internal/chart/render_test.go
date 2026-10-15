package chart

// The render proof: the image line the Deployment renders under a digest,
// under no digest, and under a malformed one.
//
// ## Why a render, when chart_test.go already reads the chart
//
// chart_test.go reads the chart as FILES, which is the right shape for
// facts that are stated (a port, an issuer, a tag). The defect this packet
// adopts is not a missing value — it is a template that did not read the
// value it was handed. Kit's chart workflow has written `image.digest`
// into every chart's values.yaml on every `push: true` run since
// roll-c5-image-digest, and its own step comment says what a chart that
// never adopted the template half gets for it: "a deployment that does not
// render image.digest ignores a value it never reads." The published chart
// held a correct, fresh digest and rendered a Deployment unchanged by it,
// which Argo's diff reported as `Synced` — the gateway pod that ran a
// six-hour-old image while the registry held the fix. A value nobody
// reads is only ever proven unread by RENDERING, which is what this file
// does: the committed values must render `repository@digest`, and the
// digest changing must change the rendered string.
//
// ## Why text/template, and what this is not
//
// Helm compiles templates with Go's own text/template and adds its
// function map. This file evaluates the same file with the same engine and
// the three functions the chart's templates reach for — helmFuncs below is
// the whole vocabulary. That is deliberately NOT a second Helm: there is
// no `include`, no `tpl`, no `toYaml`, no release metadata, no NOTES.txt,
// and a template that ever reaches for one of them errors here with
// `function "..." not defined` instead of silently under-rendering. What
// this proves is this template's branching and the exact strings it
// produces, which is the entire claim. The real `helm template` is an
// operator command outside the gate — it needs a binary the Go gate cannot
// assume on every machine — and gateway's bin/chart-test is the fleet's
// spelling of it.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

// digestGrammar is the registry's manifest digest grammar, and it is the
// one kit's `pin the image by digest` step refuses anything but:
//
//	if ! printf '%s' "$IMAGE_DIGEST" | grep -qE '^sha256:[0-9a-f]{64}$'
//
// The template refuses the same shape at the render (helpers failImage),
// and this file asserts the committed value against the same pattern, so
// the three agree by construction rather than by three near-copies.
const digestGrammar = `^sha256:[0-9a-f]{64}$`

// helmFuncs is the template vocabulary the chart uses: sprig's `regexMatch`
// and `quote`, and Helm's `fail`. Implemented over the standard library,
// because a chart that reaches for anything outside this map fails here
// with `function "..." not defined` rather than rendering something this
// test would misread as a pass. `quote` is sprig's %q over the string
// form; `fail` aborts rendering with its message, which is what a
// malformed digest triggers.
var helmFuncs = template.FuncMap{
	"quote": func(v any) string { return strconv.Quote(fmt.Sprint(v)) },
	"regexMatch": func(pattern, input string) (bool, error) {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, err
		}
		return re.MatchString(input), nil
	},
	"fail": func(msg string) (string, error) { return "", errors.New(msg) },
}

// render evaluates one chart template the way helm template evaluates it:
// the file is the source, `Values` is the only data, and helmFuncs is the
// only function map. It returns the rendered document along with the
// error a parse failure or a `fail` produces — both returns matter, and a
// caller that drops the second cannot tell a refusal from a render.
func render(t *testing.T, name string, values yamlMap) (string, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(chartRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	tmpl, err := template.New(name).Funcs(helmFuncs).Parse(string(data))
	if err != nil {
		// A template that does not parse is a broken chart, not a passing
		// one, and it is a test failure rather than a returned error: no
		// case below is about a syntax fault.
		t.Fatalf("parse %s: %v", name, err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, map[string]any{"Values": values}); err != nil {
		return "", err
	}
	return out.String(), nil
}

// renderedImage renders the Deployment over values and returns the
// container's image string — the value a pod would be scheduled with,
// read out of the RENDERED document rather than out of the template. It
// fails the test unless the render succeeds: the cases about a render that
// refuses live in TestTheImageDigestIsRefusedRatherThanRendered.
func renderedImage(t *testing.T, values yamlMap) string {
	t.Helper()
	out, err := render(t, "templates/deployment.yaml", values)
	if err != nil {
		t.Fatalf("render templates/deployment.yaml: %v", err)
	}
	doc, err := parseBytes("rendered deployment.yaml", []byte(out))
	if err != nil {
		t.Fatalf("parse the rendered Deployment: %v", err)
	}
	containers := mustChildList(t, mustChildMap(t,
		mustChildMap(t, mustChildMap(t, doc, "spec"), "template"), "spec"), "containers")
	container := mustListItem(t, containers, 0, "spec.template.spec.containers[0]")
	return mustChild(t, container, "image")
}

// valuesWithDigest copies the committed values.yaml and sets image.digest,
// so a case varies ONE fact and inherits the other eleven. An empty digest
// REMOVES the key, which is the state a chart with no digest is in and the
// one the tag branch exists for — distinct from a digest that is present
// and wrong.
func valuesWithDigest(t *testing.T, digest string) yamlMap {
	t.Helper()
	values := mustParse(t, chartRoot(t), "values.yaml")
	image, err := childMap(values, "image")
	if err != nil {
		t.Fatalf("values.yaml image block: %v", err)
	}
	if digest == "" {
		delete(image, "digest")
		return values
	}
	image["digest"] = digest
	return values
}

// TestTheDeploymentRendersTheImageByDigestWhenValuesCarryOne is the render
// half of the adoption: with a digest in values the container image is
// `repository@digest`, and changing the digest changes the rendered
// string. That second property is the one Argo's diff reads — a tag
// render was textually identical before and after a build, which is why
// the fleet ran six hours behind its own registry.
func TestTheDeploymentRendersTheImageByDigestWhenValuesCarryOne(t *testing.T) {
	values := mustParse(t, chartRoot(t), "values.yaml")
	image := mustChildMap(t, values, "image")
	repository := mustChild(t, image, "repository")
	tag := mustChild(t, image, "tag")

	t.Run("the committed digest is present and is the registry's grammar", func(t *testing.T) {
		// THE ABSENCE IS THE FAILURE, NAMED FIRST. mustChild errors on a
		// missing key, and an empty digest would satisfy every assertion
		// below by rendering the tag — a check that passes because the
		// field is absent is worse than no check.
		digest := mustChild(t, image, "digest")
		re := regexp.MustCompile(digestGrammar)
		if !re.MatchString(digest) {
			t.Errorf("values.yaml image.digest is %q, which is not %s — the "+
				"shape kit's pin-the-image-by-digest step refuses anything "+
				"but, and the shape the template requires before it will "+
				"render repository@digest", digest, digestGrammar)
		}
	})

	t.Run("the committed values render repository@digest", func(t *testing.T) {
		digest := mustChild(t, image, "digest")
		got := renderedImage(t, values)
		want := repository + "@" + digest
		if got != want {
			t.Errorf("the rendered image is %q, want %q — the chart that "+
				"reaches the box must name the image by the digest that "+
				"cannot move, which is the whole of this packet", got, want)
		}
		if strings.Contains(got, "latest") {
			t.Errorf("the rendered image is %q and carries \"latest\" — "+
				"a floating reference is a deploy that changes when "+
				"somebody else pushes", got)
		}
	})

	t.Run("a fresh digest changes the rendered image, which is the diff Argo reads", func(t *testing.T) {
		committed := mustChild(t, image, "digest")
		changed := "sha256:" + strings.Repeat("1", 64)
		got := renderedImage(t, valuesWithDigest(t, changed))
		if want := repository + "@" + changed; got != want {
			t.Errorf("the rendered image is %q, want %q — a publish that "+
				"pins a new digest must produce a Deployment that is "+
				"TEXTUALLY different, or Argo reports Synced and rolls "+
				"nothing", got, want)
		}
		if strings.Contains(got, committed) {
			t.Errorf("the rendered image %q still names the committed "+
				"digest %q — the override did not reach the render", got, committed)
		}
	})

	t.Run("no digest renders repository:tag, exactly as before", func(t *testing.T) {
		// The committed-tag path is not a fallback to be embarrassed
		// about: a fresh clone, a `push: false` run and a direct caller
		// of the chart workflow all package the chart with whatever
		// digest values.yaml commits, and a chart with none renders
		// what this repo rendered for its whole life before the field
		// existed.
		got := renderedImage(t, valuesWithDigest(t, ""))
		if want := repository + ":" + tag; got != want {
			t.Errorf("the rendered image is %q, want %q — with no digest "+
				"the Deployment must render the committed tag path, and "+
				"an empty digest must not render \"%s@\" (a reference no "+
				"registry answers)", got, want, repository)
		}
	})

	t.Run("a changed repository renders beside the digest", func(t *testing.T) {
		// The control: a render that produced the right string for the
		// wrong reason (a hardcoded name, a value the template ignored)
		// would not follow the repository.
		variant := valuesWithDigest(t, "sha256:"+strings.Repeat("2", 64))
		img, err := childMap(variant, "image")
		if err != nil {
			t.Fatalf("values.yaml image block: %v", err)
		}
		img["repository"] = "example.invalid/identity"
		got := renderedImage(t, variant)
		if want := "example.invalid/identity@sha256:" + strings.Repeat("2", 64); got != want {
			t.Errorf("the rendered image is %q, want %q — the digest "+
				"render must take the repository it is handed", got, want)
		}
	})
}

// TestTheImageDigestIsRefusedRatherThanRendered is the template-side half
// of kit's refusal. The workflow step refuses a malformed digest BEFORE it
// writes one, so the only way a value that is not `sha256:<64 hex>` can
// reach this template is a human hand-edit of values.yaml — and a template
// cannot stop that write. What it can do is refuse the render, which is
// what the Deployment does: the alternative, treating a malformed digest
// as absent and rendering the tag, would silently re-create the measured
// defect (a pinned-looking values file that renders an unpinned image,
// with Argo reporting Synced and rolling nothing). Rendering
// `repository@nonsense` is the third option and is what kit's step exists
// to prevent: a reference that looks like a pin and fails at image-pull
// with nothing naming the field.
func TestTheImageDigestIsRefusedRatherThanRendered(t *testing.T) {
	for _, bad := range []string{
		"not-a-digest",
		"sha256:",
		"sha256:" + strings.Repeat("a", 63), // one hex short
		"sha256:" + strings.Repeat("a", 65), // one hex long
		"sha256:" + strings.Repeat("A", 64), // uppercase is not the grammar's lowercase
		"sha256:" + strings.Repeat("z", 64), // not hex at all
		"sha256:" + strings.Repeat("a", 63) + " ",
	} {
		t.Run(bad, func(t *testing.T) {
			out, err := render(t, "templates/deployment.yaml", valuesWithDigest(t, bad))
			if err == nil {
				t.Fatalf("rendered a digest of %q into an image reference "+
					"instead of refusing it — the render was:\n%s", bad, out)
			}
			if out != "" {
				t.Errorf("the refused render produced %d bytes of document "+
					"as well as the error — a refusal renders nothing", len(out))
			}
			if !strings.Contains(err.Error(), "image.digest") {
				t.Errorf("the refusal does not name the field: %v", err)
			}
			if !strings.Contains(err.Error(), bad) {
				t.Errorf("the refusal does not name the value %q it refused: %v", bad, err)
			}
		})
	}
}

// TestTheCommittedDigestIsWhatAFreshCloneRenders closes the loop the
// brief states: the committed digest is this repository's current
// published image, so a clone with no publish behind it renders the pin
// rather than the tag. The value is READ from values.yaml and not typed
// here — a test that carried its own copy would agree with a values file
// that had drifted from the registry without noticing.
func TestTheCommittedDigestIsWhatAFreshCloneRenders(t *testing.T) {
	values := mustParse(t, chartRoot(t), "values.yaml")
	image := mustChildMap(t, values, "image")
	digest := mustChild(t, image, "digest")
	repository := mustChild(t, image, "repository")

	got := renderedImage(t, values)
	if want := repository + "@" + digest; got != want {
		t.Fatalf("the committed values render %q, want %q", got, want)
	}
	if strings.HasSuffix(got, ":"+mustChild(t, image, "tag")) {
		t.Errorf("the committed values render the tag path %q — with a "+
			"digest committed, the tag is the human-readable half of the "+
			"name and not the half that reaches the pod", got)
	}
	if !strings.HasPrefix(got, repository+"@sha256:") || len(got) != len(repository)+1+7+64 {
		t.Errorf("the rendered image %q is not repository plus a 64-hex "+
			"sha256 digest", got)
	}
}
