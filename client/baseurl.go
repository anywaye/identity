package client


import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// BaseURLEnvVar applies to every anywaye service.
const BaseURLEnvVar = "ANYWAYE_BASE_URL"

// ServiceBaseURLEnvVar applies to identity specifically, and is derived rather
// than written out — see `BaseURLEnvVarFor`.
const ServiceBaseURLEnvVar = "ANYWAYE_IDENTITY_BASE_URL"

// BaseURLEnvVarFor derives `ANYWAYE_<SERVICE>_BASE_URL` from a service name.
//
// Derived rather than written out per service because six string literals would be a
// second list of the six services next to the vendored documents, and this
// repository is organized entirely around not having those.
func BaseURLEnvVarFor(service string) string {
	if !regexp.MustCompile(`^[a-z]+$`).MatchString(service) {
		return ""
	}
	return "ANYWAYE_" + strings.ToUpper(service) + "_BASE_URL"
}

// ErrNoBaseURL is returned when nothing is configured.
//
// A sentinel so a caller can `errors.Is` it and print its own configuration
// advice, which is the one thing a caller can add that this package cannot.
var ErrNoBaseURL = errors.New("no base URL configured")

// LookupEnv reads one variable. It exists so tests never mutate the process
// environment, which is the same seam `internal/config`'s `Lookup` provides and
// for the same reason: `os.Setenv` in a test is a global mutation that races every
// other test in the package and leaks past the end of it.
//
// `nil` means "read the real environment", so a caller that does not care writes
// nothing and production reads `os.Getenv`.
type LookupEnv func(string) string

// BaseURLOptions is where a caller says where identity is.
//
// A struct rather than positional arguments because the set will grow — a deadline
// and a custom transport are the obvious next two — and a caller who has to
// remember the order of four strings is a caller who gets one wrong.
type BaseURLOptions struct {
	BaseURL string

	LookupEnv LookupEnv
}

// ResolveBaseURL returns the base URL requests go to, or an error naming every
// source it consulted.
//
// It is a free function rather than a method because it is a pure decision about
// configuration, and testing it does not need a client, a transport or a server.
// That is what makes the per-branch tests below cheap enough to have one per branch.
func ResolveBaseURL(opts BaseURLOptions) (string, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = osGetenv
	}

	type candidate struct {
		value  string
		source string
	}

	var considered []string
	var chosen *candidate

	for _, c := range []candidate{
		{present(opts.BaseURL), "the BaseURL option"},
		{present(lookup(ServiceBaseURLEnvVar)), "$" + ServiceBaseURLEnvVar},
		{present(lookup(BaseURLEnvVar)), "$" + BaseURLEnvVar},
	} {
		considered = append(considered, c.source)
		if c.value == "" {
			continue
		}
		if chosen == nil {
			chosen = &c
		}
	}

	if chosen == nil {
		return "", fmt.Errorf("%w for identity, and this client will not guess one;\n\n"+
			"Set one of, in order:\n"+
			"  1. the BaseURL option\n"+
			"  2. $%s\n"+
			"  3. $%s\n\n"+
			"Consulted, in that order: %s\n\n"+
			"Each of those is a decision somebody made. A default would be a guess, and "+
			"a guess about which deployment to send a customer's credentials to is the "+
			"one kind of guess this package refuses to make.\n\n"+
			"identity's own document lists https://identity.anywaye.com as a server, and "+
			"that value is deliberately NOT used as a default: it would send a "+
			"self-hoster's traffic to somebody else's deployment, and it would succeed, "+
			"so nothing would look wrong until somebody read a log",
			ErrNoBaseURL, ServiceBaseURLEnvVar, BaseURLEnvVar, strings.Join(considered, ", "))
	}

	parsed, err := url.Parse(chosen.value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("the base URL from %s is %q, which is not an absolute http(s) URL\n\n"+
			"anywaye's generated clients concatenate the base URL with an operation's path "+
			"rather than resolving one against the other, so a bare host would produce "+
			"something that is not a URL and an error naming neither the value nor the "+
			"cause. Give an absolute URL including the scheme",
			chosen.source, chosen.value)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("the base URL from %s has scheme %q, and this client speaks "+
			"only http and https\n\n"+
			"A `file:` or `javascript:` base URL is a configuration mistake that would "+
			"otherwise surface as a request error naming neither the value nor the cause",
			chosen.source, parsed.Scheme)
	}

	return strings.TrimRight(chosen.value, "/"), nil
}

func present(value string) string { return strings.TrimSpace(value) }

func osGetenv(name string) string { return os.Getenv(name) }
