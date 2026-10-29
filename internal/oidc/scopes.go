package oidc

import (
	"fmt"
	"slices"
	"strings"
)

const (
	ScopeOpenID   = "openid"
	ScopeEmail    = "email"
	ScopeProfile  = "profile"
	ScopeAccounts = "accounts"
	ScopePublish = "publish"
)

// SupportedScopes is the set above, in the order the discovery document lists
// them. It is a slice rather than a set because the order is the contract the
// document publishes, and a map's iteration order would make it differ between
// two runs of the same process.
var SupportedScopes = []string{ScopeOpenID, ScopeEmail, ScopeProfile, ScopeAccounts, ScopePublish}

// IsSupportedScope reports whether this service implements a scope.
//
// An exact match on the closed list, never a prefix. `profile` and `profiles`
// are different scopes, and a comparison that accepted the second because it
// starts with the first would hand out a claim set nobody wrote down.
func IsSupportedScope(scope string) bool {
	return slices.Contains(SupportedScopes, scope)
}

// NormalizeScopes deduplicates and sorts a list of scopes, dropping the ones
// this service does not implement.
//
// Dedup because a client registering `openid openid` should not see it twice in
// its own event payload, and sort because the list reaches the discovery
// document and a map's iteration order would make the document differ between
// two runs of the same registration.
//
// Dropping rather than refusing is right HERE and only here: this is the
// registration path, where a client states what it would like and the operator
// curates what it gets. The authorization endpoint, where a caller asks for a
// token right now, refuses — see ValidateRequestedScopes.
func NormalizeScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if IsSupportedScope(scope) && !slices.Contains(out, scope) {
			out = append(out, scope)
		}
	}
	slices.Sort(out)
	return out
}

// FirstUnsupported returns the first requested scope this service does not
// implement, or "" when they are all supported.
//
// The name is returned rather than a boolean because the caller of this is the
// authorize endpoint, and the person reading the 400 is a developer configuring
// a product: "unknown scope: phone" is a five-minute fix and "invalid request"
// is an afternoon. The order is the caller's order, not the sorted one, so the
// name reported is the first one they actually wrote.
func FirstUnsupported(scopes []string) string {
	for _, scope := range scopes {
		if !IsSupportedScope(scope) {
			return scope
		}
	}
	return ""
}

// ValidateRequestedScopes is the gate on an authorization request: every scope
// must be one this service implements, and `openid` must be among them.
//
// Two rules, both refusals rather than corrections. The library's own
// ValidateAuthReqScopes silently DELETES a scope it does not recognize and
// carries on, which is the wrong answer for a provider whose whole job is to be
// legible to another program: a client that asked for `phone` would get a token
// with no phone claim and no indication that anything was dropped. The check
// here runs before the request is stored, so the flow stops at the door rather
// than half way through.
func ValidateRequestedScopes(scopes []string) error {
	if unknown := FirstUnsupported(scopes); unknown != "" {
		return fmt.Errorf("unknown scope %q; this provider implements %s",
			unknown, strings.Join(SupportedScopes, " "))
	}
	if !slices.Contains(scopes, ScopeOpenID) {
		return fmt.Errorf("the openid scope is required; this is an OpenID Connect provider and " +
			"a request without it gets no id_token and no userinfo")
	}
	return nil
}
