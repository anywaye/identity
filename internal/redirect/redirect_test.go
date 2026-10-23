package redirect

import "testing"

// The table is the rule. Every case pins one shape a browser and this
// function could disagree about, and the answer is the safe one for each:
// when in doubt the function refuses, because a refused redirect costs the
// caller a default and an allowed one costs the user their origin.
func TestAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{
		// --- the allowed shape: a string that begins with exactly one "/"

		{
			// The happy path: a same-origin path.
			name: "a same-origin path",
			give: "/ok",
			want: true,
		},
		{
			// The root, and the conventional default a caller substitutes
			// when a target is refused.
			name: "the root",
			give: "/",
			want: true,
		},
		{
			// The path is same-origin; what the caller does with `next` is
			// the caller's own policy. The query string is not this
			// function's decision.
			name: "a same-origin path with an absolute URL in the query",
			give: "/ok?next=https://evil.test",
			want: true,
		},
		{
			// A fragment never changes the origin.
			name: "a same-origin path with a fragment",
			give: "/ok#section",
			want: true,
		},

		// --- the refusals, and why each shape is hostile

		{
			// Refused, and the helper never substitutes a default: the
			// caller applies its own, conventionally "/". A default chosen
			// here would be inherited by every future caller, reviewed or
			// not.
			name: "the empty string",
			give: "",
			want: false,
		},
		{
			// An absolute URL names its own origin, and that origin is not
			// this one.
			name: "an absolute URL to another origin",
			give: "https://evil.test/x",
			want: false,
		},
		{
			// The host resembles the product's but is not exactly it, and
			// resemblance is the attack: a lookalike domain is what the
			// user is being asked to trust.
			name: "an absolute URL to a lookalike host",
			give: "https://identity.example.com/x",
			want: false,
		},
		{
			// The same lookalike with the real host as a suffix — the shape
			// a user scans for and does not find.
			name: "an absolute URL with the product's host as a suffix",
			give: "https://identity.example.com.evil.test/x",
			want: false,
		},
		{
			// An absolute URL to the product's OWN host is still refused,
			// and that is the load-bearing case: this function is pure, so it
			// has no request origin to compare against, and "same-origin" is
			// not decidable here. The allowed set is relative paths only,
			// precisely so the answer never depends on a host allow-list.
			name: "an absolute URL to the product's own host",
			give: "https://identity.anywaye.com/x",
			want: false,
		},
		{
			// Protocol-relative: the browser reads "//evil.test/x" as
			// "scheme://evil.test/x" — another origin wearing a path's
			// clothes.
			name: "a protocol-relative URL",
			give: "//evil.test/x",
			want: false,
		},
		{
			// The WHATWG parser's special-authority-ignore-slashes state
			// skips any run of slashes after the first two, so the browser
			// sees "//evil.test/x" here too.
			name: "three slashes",
			give: "///evil.test/x",
			want: false,
		},
		{
			// The backslash fold: WHATWG parsers treat "\" as "/" for the
			// special schemes, so "/\evil.test" is "//evil.test" in every
			// standard browser. Go's url.Parse does not fold it, so a check
			// written against Go's parser alone would wave it through.
			name: "a backslash where the second slash should be",
			give: `/\evil.test`,
			want: false,
		},
		{
			// The same fold one character later.
			name: "a backslash after the first slash",
			give: `/\/evil.test`,
			want: false,
		},
		{
			// Backslashes from the start: the fold makes this
			// "//evil.test/x" as well. It has no leading "/", so the first
			// check refuses it before the backslash check is reached.
			name: "backslashes instead of slashes",
			give: `\\evil.test/x`,
			want: false,
		},
		{
			// Browsers strip leading C0 controls and spaces before parsing,
			// so the browser sees "//evil.test/x" where the string says
			// something else. This is the bypass class for checks that trim
			// or parse leniently.
			name: "leading whitespace before a protocol-relative URL",
			give: "  //evil.test/x",
			want: false,
		},
		{
			// A bare relative reference is same-origin only after the
			// browser resolves it against the request path — which this
			// function cannot see. The allowed set is one shape so that the
			// answer never depends on the request.
			name: "a relative reference with no leading slash",
			give: "ok",
			want: false,
		},
		{
			// A scheme is not a path. It has no leading "/", and no origin
			// question to ask: the answer is no.
			name: "a javascript scheme",
			give: "javascript:alert(1)",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := Allow(tt.give); got != tt.want {
				t.Errorf("Allow(%q) = %v, want %v", tt.give, got, tt.want)
			}
		})
	}
}
