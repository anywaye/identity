// Package redirect is the one place that answers one question: may the
// post-change redirect go to this URL?
//
// After a sensitive change — a password reset, an email change, an MFA
// enrollment — the product sends the browser somewhere. When that somewhere
// comes from the request, an ad hoc check per route is how the service
// becomes an open redirector: one route that forgets, or one validator that
// disagrees with the browser, and a "confirm your password" page ends on
// evil.test. This package is the rule as a pure function, so that wiring it
// is a one-line change per route rather than a security review per route.
//
// THE RULE: same-origin relative paths are allowed; everything else is
// refused. The allowed set is exactly one shape — a string that begins with a
// single "/" — and the whole implementation is three prefix checks.
//
// "Same-origin" here means RELATIVE, and that is a choice with a reason. This
// function is pure: no request, no Host header, no configured origin to
// compare against. An absolute URL therefore cannot be answered "yes"
// honestly even when the host is exactly the product's, and a host allow-list
// would be a second thing to get stale, per deployment and per environment.
// The OIDC client table is the only allow-list of hosts this service keeps,
// and it is per-client by design. A relative path is the one shape that cannot
// name another host, so a relative path is the only shape allowed.
//
// THE QUERY STRING IS NOT THIS FUNCTION'S DECISION. `/ok?next=https://evil.test`
// is allowed because the path is same-origin; what the caller does with
// `next` is the caller's own policy, and this package does not have the
// context to make it. Fragments are the same.
//
// THE EMPTY STRING IS REFUSED, and the helper never substitutes a default.
// The caller applies its own — conventionally "/" — because a default chosen
// here would be inherited by every future caller, reviewed or not, and a
// silent safe answer is the thing this package exists to eliminate.
//
// There is deliberately no clock, no database and no HTTP in this package, so
// any service in the fleet can copy or import it without ceremony.
package redirect

import "strings"

// Allow reports whether target is a safe destination for a post-change
// redirect. The rule and its reasons are the package comment; the
// implementation below is that rule, in three checks.
func Allow(target string) bool {
	// A leading "/" is the whole allowed shape. An absolute URL
	// ("https://evil.test/x") does not have one, a protocol-relative one
	// ("//evil.test/x") has two, and the empty string has none — so this
	// one check refuses more than the next two combined.
	if !strings.HasPrefix(target, "/") {
		return false
	}

	// "//" is protocol-relative: the browser reads "//evil.test/x" as
	// "scheme://evil.test/x", which is another origin wearing a path's
	// clothes. "///evil.test/x" is refused by the same check and for a
	// related reason — the WHATWG parser's special-authority-ignore-slashes
	// state skips any run of slashes after the first two, so the browser
	// sees "//evil.test/x" there too.
	if strings.HasPrefix(target, "//") {
		return false
	}

	// "/\" is the same attack with a backslash. The WHATWG URL parser folds
	// "\" to "/" for the special schemes, so "/\evil.test" is "//evil.test"
	// in every standard browser — and Go's url.Parse does NOT fold it, so a
	// check written against Go's parser alone would wave it through. The
	// parsers disagree about the shape, which is exactly why the shape is
	// hostile: a validator that agrees with only one parser is a check that
	// fails on the others.
	if strings.HasPrefix(target, `/\`) {
		return false
	}

	return true
}
