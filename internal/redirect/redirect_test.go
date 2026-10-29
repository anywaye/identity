package redirect

import "testing"

func TestAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give string
		want bool
	}{

		{
			name: "a same-origin path",
			give: "/ok",
			want: true,
		},
		{
			name: "the root",
			give: "/",
			want: true,
		},
		{
			name: "a same-origin path with an absolute URL in the query",
			give: "/ok?next=https://evil.test",
			want: true,
		},
		{
			name: "a same-origin path with a fragment",
			give: "/ok#section",
			want: true,
		},


		{
			name: "the empty string",
			give: "",
			want: false,
		},
		{
			name: "an absolute URL to another origin",
			give: "https://evil.test/x",
			want: false,
		},
		{
			name: "an absolute URL to a lookalike host",
			give: "https://identity.example.com/x",
			want: false,
		},
		{
			name: "an absolute URL with the product's host as a suffix",
			give: "https://identity.example.com.evil.test/x",
			want: false,
		},
		{
			name: "an absolute URL to the product's own host",
			give: "https://identity.anywaye.com/x",
			want: false,
		},
		{
			name: "a protocol-relative URL",
			give: "//evil.test/x",
			want: false,
		},
		{
			name: "three slashes",
			give: "///evil.test/x",
			want: false,
		},
		{
			name: "a backslash where the second slash should be",
			give: `/\evil.test`,
			want: false,
		},
		{
			name: "a backslash after the first slash",
			give: `/\/evil.test`,
			want: false,
		},
		{
			name: "backslashes instead of slashes",
			give: `\\evil.test/x`,
			want: false,
		},
		{
			name: "leading whitespace before a protocol-relative URL",
			give: "  //evil.test/x",
			want: false,
		},
		{
			name: "a relative reference with no leading slash",
			give: "ok",
			want: false,
		},
		{
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
