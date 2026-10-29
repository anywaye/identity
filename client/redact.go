package client


import (
	"regexp"
	"sort"
	"strings"
)

// Redacted is the replacement for any string that matched. It is exported because
// a consumer has to be able to recognize it — a log line containing this marker is
// a log line about redaction, and a caller who wants to assert on it needs the exact
// string.
//
// It is deliberately not an empty string. A message that is suddenly blank reads as
// "the error had no detail", which is a different and wrong conclusion, and the
// operator who then goes looking for a missing field is looking for the wrong thing.
const Redacted = "[redacted: a credential-shaped value was present]"

var credentialShapes = regexp.MustCompile(
	`\banywaye_[A-Za-z0-9_-]+` +
		`|\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*` +
		`|(?:^|[\s,;])(?:proxy-)?authorization\s*:\s*\S+` +
		`|(?:^|[\s,;])(?:set-)?cookie\s*:\s*[^\r\n]*`)

// Redactor removes credentials from anything this package is about to hand a human.
//
// ONE field, and it is a function. See the file header: a func value is rendered as
// an address by every `fmt` verb including `%#v`, so the credential cannot be
// printed out of this type by any formatting path.
//
// The zero value is usable and redacts nothing but credential SHAPES, which is what
// the structural fallback exists for.
type Redactor struct {
	holdsKnown func(string) bool
}

// NewRedactor binds a redactor to the credential values this instance holds.
//
// Blank and empty values are dropped rather than kept: an empty secret would match
// at position zero in every string and redact all of them, which is the kind of bug
// that looks like a security feature and is a denial of service.
//
// Longest first, so a secret that is a prefix of another cannot be replaced
// part-way and leave a tail behind. With the all-or-nothing rule that particular bug
// is harmless — either string still matches — but ordering by length costs nothing
// and keeps the intent obvious.
func NewRedactor(known ...string) Redactor {
	seen := map[string]bool{}
	var exact []string

	for _, secret := range known {
		if secret == "" || seen[secret] {
			continue
		}
		seen[secret] = true
		exact = append(exact, secret)
	}

	if len(exact) == 0 {
		return Redactor{}
	}

	sort.SliceStable(exact, func(i, j int) bool { return len(exact[i]) > len(exact[j]) })

	return Redactor{holdsKnown: func(value string) bool {
		for _, secret := range exact {
			if strings.Contains(value, secret) {
				return true
			}
		}
		return false
	}}
}

// String returns the text unchanged, or Redacted if anything credential-shaped is in
// it. It never returns a partially-redacted string.
//
// The empty case is `""` rather than the marker: "no value" is not a secret, and
// redacting the absence of a thing would make a redaction marker meaningless.
func (r Redactor) String(value string) string {
	if value == "" {
		return ""
	}

	if r.holdsKnown != nil && r.holdsKnown(value) {
		return Redacted
	}

	if credentialShapes.MatchString(value) {
		return Redacted
	}

	return value
}

// Error renders an error's message, or Redacted if it carried a credential.
//
// This is the method that matters most and it exists because it is the one Go calls
// implicitly. `slog.Any("error", err)`, `fmt.Printf("%v", err)` and
// `log.Println(err)` all reach `Error()`, so redacting here covers every path that
// does not go through this package's own formatting — including the ones this
// package does not know about.
func (r Redactor) Error(err error) string {
	if err == nil {
		return ""
	}
	return r.String(err.Error())
}

// SafeCause keeps a wrapped error as a cause, unless there is something in it to
// keep out of one.
//
// A cause is how the errno survives: `net/http`'s `*url.Error` says almost nothing,
// and the difference between a refused connection and a DNS failure is one level
// down in `Err`. So the original is normally preserved untouched and a caller who
// wants `errors.Is(err, syscall.ECONNREFUSED)` still has it.
//
// Except when the redactor finds a credential in it. A cause is a real object this
// package does not own and it is reachable — `%+v` on it prints it, every crash
// reporter prints it, `slog` prints it. Passing a partially-scrubbed copy would be
// the worst of both: a cause that is no longer the platform's, carrying a message
// that is no longer true. So when there is anything to withhold the original is
// withheld ENTIRELY, and what is kept is a stand-in that says so.
//
// The stand-in does NOT unwrap. That is the point, and it is a cost worth naming:
// `errors.Is` and `errors.As` will not reach through it. Preserving the ability to
// unwrap would preserve the ability to print the original message, which is the
// thing being prevented.
func (r Redactor) SafeCause(err error) error {
	if err == nil {
		return nil
	}
	if r.String(err.Error()) == err.Error() {
		return err
	}
	return &redactedCause{}
}

type redactedCause struct{}

func (*redactedCause) Error() string {
	return Redacted + " — the original error carried a credential-shaped value, so it is not " +
		"attached, and it is deliberately not unwrappable: errors.Is would otherwise put " +
		"the original message back into any error chain somebody formats."
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
