package redirect

import "strings"

// Allow reports whether target is a safe destination for a post-change
// redirect. The rule and its reasons are the package comment; the
// implementation below is that rule, in three checks.
func Allow(target string) bool {
	if !strings.HasPrefix(target, "/") {
		return false
	}

	if strings.HasPrefix(target, "//") {
		return false
	}

	if strings.HasPrefix(target, `/\`) {
		return false
	}

	return true
}
