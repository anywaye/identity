package agents

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const (
	usernameMin = 3
	usernameMax = 39
	usernameBaseMax = 24
	usernameSuffixLen = 6
	usernameAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// ErrInvalidUsername is a caller-supplied handle that does not fit the shape.
var ErrInvalidUsername = fmt.Errorf("a username must be 3-39 characters of lower-case letters, digits and dashes, not starting or ending with a dash")

// NormalizeUsername renders a caller's or a name's text into a handle candidate.
//
// It collapses every run of non-alphanumeric characters to a single dash, trims
// leading and trailing dashes, lower-cases, and truncates the base to
// usernameBaseMax. It returns "" when nothing alphanumeric survives, which is the
// caller's signal to fall back to the generated form — an agent named "!!!" gets
// a generated handle rather than an invalid one.
//
// It does NOT validate length or the leading/trailing rule; AppendSuffix and
// the generated path produce values that satisfy both, and a caller who supplies
// a bare handle is validated separately. This is a projection, and the guarantee
// it gives is only "no character outside the allowed set appears".
func NormalizeUsername(raw string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if b.Len() > 0 && !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > usernameBaseMax {
		slug = strings.Trim(slug[:usernameBaseMax], "-")
	}
	return slug
}

// ValidUsername reports whether a caller-supplied handle fits the shape the
// column's CHECK enforces. Exact and case-sensitive: `Alex` is not `alex`, and a
// handle that is not already lower-cased is refused rather than silently fixed,
// because a caller who typed `Alex` meant `Alex` and a handle that changed on the
// way to storage is the kind of surprise that becomes a bug report.
func ValidUsername(given string) bool {
	if len(given) < usernameMin || len(given) > usernameMax {
		return false
	}
	if given != strings.ToLower(given) {
		return false
	}
	for i, r := range given {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			continue
		}
		if r == '-' && i > 0 && i < len(given)-1 {
			continue
		}
		return false
	}
	return true
}

// GenerateUsernameBase builds the deterministic half of a generated handle: the
// normalised display name, or "agent" when nothing survives.
func GenerateUsernameBase(name string) string {
	if base := NormalizeUsername(name); base != "" {
		return base
	}
	return "agent"
}

func randomSuffix() string {
	buf := make([]byte, usernameSuffixLen)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("0", usernameSuffixLen)
	}
	out := make([]byte, usernameSuffixLen)
	for i, b := range buf {
		n := int64(b) % int64(len(usernameAlphabet))
		out[i] = usernameAlphabet[n]
	}
	return string(out)
}

func appendSuffix(base string) string {
	room := usernameMax - len(base) - 1
	if room < usernameSuffixLen {
		base = strings.Trim(base[:usernameMax-usernameSuffixLen-1], "-")
	}
	return base + "-" + randomSuffix()
}
