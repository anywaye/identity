package httpapi

// THE REDEMPTION OVER A REAL DATABASE, AND THE BYTE AGREEMENT WITH THE LOGIN.
//
// # WHY THIS FILE EXISTS AND WHAT A DOUBLE CANNOT REPLACE
//
// `sessionlinks_redeem_test.go` drives a double, which is the right instrument for
// "does the route translate". This one drives the real router, the real recovery use
// case, the real sessions store and the real MFA store over a private schema, and it
// exists for the claims a double cannot make at all:
//
//   - a redemption produces a session that RESOLVES, which means asking the store a
//     client would be served by rather than reading the redemption's return value;
//   - the refusals are indistinguishable over real ROWS — an expired link, a spent
//     one, a disabled subject, a subject who enrolled and a wrong-purpose token are
//     five different facts about the DATABASE, and only real rows can be five
//     different facts;
//   - the MFA race is proven LIVE, against a confirmed `mfa_credentials` row written
//     by the real enrollment flow, rather than against a flag;
//   - and the byte agreement with `POST /v1/session`, which is the claim the whole
//     route's contract rests on.
//
// # THE FIXTURE'S ONE DELIBERATE DEPARTURE
//
// The auth service here is built with `recovery.RedeemedSessionTTL` rather than
// `authServiceFor`'s 24 hours. That is not tidiness — it is what lets the byte walk
// compare `expires_at` as well as the shape, because with the same clock and the
// same TTL the two instants are the same instant. Otherwise the walk would have to
// normalise the timestamp away, and a route that minted a session lasting a
// different length from a password login's would pass it.
//
// `TestTheRedeemedSessionLastsExactlyAsLongAsAPasswordLoginMints` states the
// relationship separately, against the two constants, so the fixture's choice and
// the claim it is enabling are two things a reader can check independently.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/anywaye/identity/internal/auth"
	"github.com/anywaye/identity/internal/mfa"
	"github.com/anywaye/identity/internal/oidc"
	"github.com/anywaye/identity/internal/outbox"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/db"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/recovery"
	"github.com/anywaye/identity/internal/sessions"
	"github.com/anywaye/identity/internal/useraudit"
	"github.com/anywaye/identity/internal/users"
)

// redeemFixture is the whole redemption surface over ONE private schema: the real
// auth service, the real recovery service, and the REAL mfa service as the
// second-factor seam.
//
// The mfa service is the real one and not `noEnrolledSecondFactor{}` for one reason,
// and it is the reason the race test below is worth anything: a seam answering from a
// boolean can only prove that the REDEMPTION reads its answer, while the real lookup
// proves the answer is true of a `mfa_credentials` row somebody enrolled through the
// real flow, milliseconds earlier.
type redeemFixture struct {
	handler http.Handler
	pool    *pgxpool.Pool
	clk     *clock.Fake
	links   *recovery.Service
	mfa     *mfa.Service
	mailer  *captureMailer
}

func newRedeemFixture(t *testing.T) *redeemFixture {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	secondFactor := testMFAService(pool, clk)
	mailer := &captureMailer{}
	cheap := users.NewHasherWithParams(&argon2id.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})

	authSvc := auth.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		users.NewStore(pool),
		sessions.NewStore(pool),
		outbox.NewStore(pool),
		realTenancy(pool, clk),
		secondFactor,
		// The real sweep over the real table, as main wires it. A disable in this
		// package must behave the way the deployed service does, and a nil here
		// would make it refuse rather than revoke.
		oidc.NewStore(pool),
		useraudit.NewStore(pool),
		cheap,
		clk,
		recovery.RedeemedSessionTTL,
		false,
	)

	links := recovery.NewService(
		db.TxRunner{Pool: pool},
		db.Direct{Pool: pool},
		recovery.NewStore(pool),
		users.NewStore(pool),
		sessions.NewStore(pool),
		&captureAccessRevoker{revoked: map[string]time.Time{}},
		outbox.NewStore(pool),
		mailer,
		cheap,
		clk,
		secondFactor,
	)

	return &redeemFixture{
		handler: New(nil,
			WithAuth(authSvc),
			WithRecovery(links),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		pool:   pool,
		clk:    clk,
		links:  links,
		mfa:    secondFactor,
		mailer: mailer,
	}
}

// linkSubject is one registered account: its row id, its address and its password.
type linkSubject struct {
	id       id.UUID
	email    string
	password string
}

// register creates an account through the real route, so the fixture's rows are ones
// the service wrote rather than ones a test inserted.
func (f *redeemFixture) register(t *testing.T) linkSubject {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, f.handler, "/v1/users", `{"email":"`+email+`","password":"`+validPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering = %d, want 201; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	who, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service issued an unparseable user id %q: %v", created.ID, err)
	}
	return linkSubject{id: who, email: email, password: validPassword}
}

// mint links one token to this subject, through the real use case.
//
// THROUGH THE SERVICE RATHER THAN THE ROUTE, and the reason is that the mint route is
// behind a scoped api key whose minting needs tenancy, an account and a key — a great
// deal of fixture for a value this file is about the OTHER half of. The token it
// produces is the one the route hands a caller, because it is the same insert;
// `TestAMintReturnsTheTokenAndTheInstantItDies` is where the route's own half is held.
func (f *redeemFixture) mint(t *testing.T, who linkSubject) string {
	t.Helper()

	link, err := f.links.MintSessionLink(t.Context(), recovery.MintSessionLinkInput{UserID: who.id})
	if err != nil {
		t.Fatalf("MintSessionLink: %v", err)
	}
	return link.Token
}

// redeem presents a token to the public route with no credential at all, which is how
// a browser following the caller's link arrives.
func (f *redeemFixture) redeem(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, f.handler, "/v1/session-links/redeem", `{"token":"`+token+`"}`)
}

// spent reads the link row's `token_consumed_at` for one subject, which is the claim
// "a refused redemption spends nothing" read back out of the TABLE rather than out
// of the response.
func (f *redeemFixture) spent(t *testing.T, who linkSubject) *time.Time {
	t.Helper()

	var consumed *time.Time
	if err := f.pool.QueryRow(t.Context(), `
		SELECT t.token_consumed_at FROM recovery_tokens t
		WHERE t.user_id = $1 AND t.purpose = 'session_link'`, who.id).Scan(&consumed); err != nil {
		t.Fatalf("reading the link row: %v", err)
	}
	return consumed
}

// setDisabled writes or clears `disabled_at` directly.
//
// THROUGH SQL RATHER THAN `users.Store.Disable` because this file is about the
// redemption and the column is a given: the instant a person wrote and the NULL they
// left behind are `identity-disabled-01`'s semantics and are tested there. Using the
// store here would add a second subject to this file's assertions for no extra
// coverage of the code under test.
func (f *redeemFixture) setDisabled(t *testing.T, who linkSubject, disabled bool) {
	t.Helper()

	value := any(nil)
	if disabled {
		value = time.Date(2026, 10, 1, 12, 5, 0, 0, time.UTC)
	}
	if _, err := f.pool.Exec(t.Context(),
		`UPDATE users SET disabled_at = $2 WHERE id = $1`, who.id, value); err != nil {
		t.Fatalf("writing disabled_at: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the byte agreement
// ---------------------------------------------------------------------------

// TestTheRedeemedSessionIsByteForByteTheSessionAPasswordLoginMints is the walk.
//
// IT COMPARES THE RAW BYTES, with one substitution: the credential itself. Both
// responses carry a different token — they cannot carry the same one, that is what a
// session is — so every other byte is compared exactly, including the `expires_at`
// timestamp and the whole `Set-Cookie` line down to its attribute order and its
// `Expires=` rendering.
//
// A FIELD-BY-FIELD comparison of decoded maps would pass against a cookie that
// differed in `SameSite` or in `MaxAge`, because the cookie is not in the body. A
// comparison of the two functions' NAMES would pass against a handler that called
// them in the wrong ORDER, and the order is load-bearing: the cookie is written
// before the body so a client which crashes mid-write is left signed out rather than
// holding a token it never saw.
//
// The walk is logged, because "they agree" is a claim and a claim with no output is a
// comment.
func TestTheRedeemedSessionIsByteForByteTheSessionAPasswordLoginMints(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	// THE LOGIN. A real password, through the real route.
	login := post(t, f.handler, "/v1/session",
		`{"email":"`+who.email+`","password":"`+who.password+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	var loginSession sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &loginSession); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	// THE REDEMPTION. A real link, through the real route, with no credential.
	redeemed := f.redeem(t, f.mint(t, who))
	if redeemed.Code != http.StatusOK {
		t.Fatalf("POST /v1/session-links/redeem = %d, want 200; body: %s", redeemed.Code, redeemed.Body)
	}
	var linkSession sessionResponse
	if err := json.Unmarshal(redeemed.Body.Bytes(), &linkSession); err != nil {
		t.Fatalf("the redemption body is not JSON: %v", err)
	}

	// NEGATIVE CONTROL FIRST. If the two tokens were equal, every comparison below
	// would be a tautology about one value — and the route would have minted a second
	// session carrying somebody else's credential, so this has to be able to fail.
	if loginSession.Token == linkSession.Token {
		t.Fatal("the login and the redemption produced the SAME session token, so every " +
			"comparison below would be about one value rather than about two responses")
	}

	loginWalk := walkOfSession(t, login, loginSession.Token)
	redeemWalk := walkOfSession(t, redeemed, linkSession.Token)

	t.Logf("POST /v1/session\n%s", loginWalk)
	t.Logf("POST /v1/session-links/redeem\n%s", redeemWalk)

	if loginWalk != redeemWalk {
		t.Errorf("a redeemed session is not byte-for-byte a session a password login mints:\n"+
			"--- POST /v1/session ---\n%s\n--- POST /v1/session-links/redeem ---\n%s\n"+
			"Everything except the credential itself must match exactly. A difference here is a "+
			"client that signs in with a password and is signed out after following a link.",
			loginWalk, redeemWalk)
	}

	// AND THE WALK ACTUALLY SAW SOMETHING, which is the failure this package has already
	// paid for once: a comparison of two empty strings is how a check over nothing goes
	// green.
	for _, field := range []string{
		"status:", "content-type:", "set-cookie:", "body:", "expires_at:", "other headers:",
	} {
		if !strings.Contains(loginWalk, field) {
			t.Errorf("the walk never rendered %q, so the agreement above is narrower than it "+
				"claims to be:\n%s", field, loginWalk)
		}
	}
}

// TestTheRedeemedSessionLastsExactlyAsLongAsAPasswordLoginMints states the TTL
// relationship on its own, against the two constants.
//
// THE TWO CONSTANTS ARE IN TWO PACKAGES ON PURPOSE: `recovery.RedeemedSessionTTL` and
// `auth.DefaultSessionTTL`, because neither package has a reason to import the other
// for a duration. That is a real cost — two numbers that can drift — and this is what
// pays it. Without it, a session redeemed through a link would quietly last a
// different length from one made with a password, which is the kind of difference
// nobody reports and every incident review notices.
func TestTheRedeemedSessionLastsExactlyAsLongAsAPasswordLoginMints(t *testing.T) {
	if recovery.RedeemedSessionTTL != auth.DefaultSessionTTL {
		t.Errorf("recovery.RedeemedSessionTTL is %s and auth.DefaultSessionTTL is %s. A link "+
			"redeems into the session a password login would have produced, and a session that "+
			"expires at a different moment from this service's own other route is not that",
			recovery.RedeemedSessionTTL, auth.DefaultSessionTTL)
	}
}

// walkOfSession renders the parts of a response that make it a session, with the
// credential replaced by a placeholder so two of them can be compared.
//
// THE COOKIE LINE IS TAKEN FROM THE RAW HEADER rather than from a parsed
// `http.Cookie`, and that is the load-bearing choice in this helper: a parsed cookie
// normalises attribute order, drops what it does not recognize and re-renders
// `Expires` in its own format, so a difference in any of those would have been erased
// before the comparison ran. What the browser is asked to store is the bytes.
//
// TWO HEADERS ARE EXCLUDED, AND THEY ARE EXCLUDED FOR DIFFERENT REASONS:
//
//	Content-Length  it is arithmetic about a value that differs by construction. Two
//	                tokens of the same shape have the same length today; nothing about
//	                this walk would notice if they stopped.
//	X-Trace-Id      it is a property of the REQUEST, not of the route: every request
//	                gets a fresh trace, so two responses from two routes can never
//	                agree on it. It is not dropped silently — the helper asserts one is
//	                present and renders it as present — because a route that answered
//	                without one would be an operational finding, and a walk that
//	                excluded the header outright could not see that.
func walkOfSession(t *testing.T, rec *httptest.ResponseRecorder, token string) string {
	t.Helper()

	var session sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatalf("the body is not JSON: %v\n%s", err, rec.Body)
	}

	var cookies, others []string
	for name, values := range rec.Header() {
		switch strings.ToLower(name) {
		case "content-type", "content-length":
			continue
		case "set-cookie":
			for _, value := range values {
				cookies = append(cookies, strings.ReplaceAll(value, token, "<the-session-token>"))
			}
		case strings.ToLower(TraceHeader):
			for _, value := range values {
				if value == "" {
					t.Errorf("%s is present and empty: an operator cannot search for this request",
						TraceHeader)
				}
				others = append(others, name+"=<a fresh id per request, present>")
			}
		default:
			others = append(others, name+"="+strings.Join(values, ","))
		}
	}

	return strings.Join([]string{
		"status:        " + strconv.Itoa(rec.Code),
		"content-type:  " + rec.Header().Get("Content-Type"),
		"set-cookie:    " + strings.Join(cookies, " | "),
		"body:          " + strings.ReplaceAll(strings.TrimSpace(rec.Body.String()), token, "<the-session-token>"),
		"expires_at:    " + session.ExpiresAt.UTC().Format(time.RFC3339),
		"token:         <" + strconv.Itoa(len(session.Token)) + " chars, present=" +
			strconv.FormatBool(session.Token != "") + ">",
		"other headers: " + strings.Join(others, ","),
	}, "\n")
}

// ---------------------------------------------------------------------------
// the ways of being wrong, over real rows
// ---------------------------------------------------------------------------

// TestTheRedemptionCannotBeToldApartFromALinkThatNeverExisted is the wire-level
// indistinguishability, over REAL ROWS.
//
// Each case below is a different fact about the DATABASE and not about a string: an
// `expires_at` in the past, a set `token_consumed_at`, a `disabled_at`, a confirmed
// `mfa_credentials` row, a `purpose` of `password_reset`. A table of garbage strings
// would pass against an implementation that refused everything, which is why the
// comparison is over the RENDERED PROBLEM DOCUMENT and why the first case is a
// reference rather than a special case.
//
// It is compared over the document rather than over the status because a status and a
// body are two different things to get wrong, and this route's refusals have to be
// indistinguishable in both or in neither.
func TestTheRedemptionCannotBeToldApartFromALinkThatNeverExisted(t *testing.T) {
	cases := []struct {
		name    string
		present func(t *testing.T, f *redeemFixture) string
	}{
		{
			name: "REFERENCE: a token that never existed",
			present: func(_ *testing.T, _ *redeemFixture) string {
				return strings.Repeat("z", 43)
			},
		},
		{
			name: "an expired link",
			present: func(t *testing.T, f *redeemFixture) string {
				token := f.mint(t, f.register(t))
				f.clk.Advance(recovery.SessionLinkTTL + time.Second)
				return token
			},
		},
		{
			name: "a link that has been spent",
			present: func(t *testing.T, f *redeemFixture) string {
				token := f.mint(t, f.register(t))
				if rec := f.redeem(t, token); rec.Code != http.StatusOK {
					t.Fatalf("spending the link in its own fixture = %d, want 200; body: %s",
						rec.Code, rec.Body)
				}
				return token
			},
		},
		{
			name: "a link for a subject who was disabled after the mint",
			present: func(t *testing.T, f *redeemFixture) string {
				who := f.register(t)
				token := f.mint(t, who)
				f.setDisabled(t, who, true)
				return token
			},
		},
		{
			name: "a link for a subject who enrolled a second factor after the mint",
			present: func(t *testing.T, f *redeemFixture) string {
				who := f.register(t)
				token := f.mint(t, who)
				enrollMFA(t, f.mfa, who.id, f.clk.Now())
				return token
			},
		},
		{
			// A REAL password_reset row for a real subject, so the only thing refusing
			// it is the purpose. A random string would be refused by the digest miss
			// instead and would prove nothing about the closed set.
			name: "a password reset token presented here",
			present: func(t *testing.T, f *redeemFixture) string {
				who := f.register(t)
				if err := f.links.RequestPasswordReset(t.Context(), who.email); err != nil {
					t.Fatalf("RequestPasswordReset: %v", err)
				}
				return tokenIn(t, f.mailer.last(t))
			},
		},
	}

	var reference string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRedeemFixture(t)
			rec := f.redeem(t, tc.present(t, f))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("a %s = %d, want 404; body: %s", tc.name, rec.Code, rec.Body)
			}
			// No session. A refusal that handed one over is not a refusal, and the
			// status code cannot say so.
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Errorf("the 404 set %d cookie(s)", len(cookies))
			}

			problem := decodeProblem(t, rec)
			problem.TraceID = ""
			rendered := renderProblem(t, problem)

			switch {
			case reference == "":
				reference = rendered
				t.Logf("every refusal answers, byte for byte: %s", rendered)
			case rendered != reference:
				t.Errorf("a %s answers differently from a token that never existed:\n"+
					"     this: %s\n  the same: %s\n"+
					"The token IS the credential on this route, so a caller holding a dead link "+
					"learns nothing about the account it was for — and a caller who can tell the "+
					"two apart learns exactly that.", tc.name, rendered, reference)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the redemption, over real rows
// ---------------------------------------------------------------------------

// TestARedeemedSessionSignsTheBrowserIn is the end-to-end claim: the value the
// redemption returned is a session `GET /v1/me` accepts, which is the only assertion
// that says "a link is a password you can click" rather than "a link wrote a row".
func TestARedeemedSessionSignsTheBrowserIn(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	rec := f.redeem(t, f.mint(t, who))
	if rec.Code != http.StatusOK {
		t.Fatalf("redeeming = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	// The COOKIE, because that is what a browser following a link carries.
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("the redemption set %d cookies, want 1", len(cookies))
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/me", nil)
	req.AddCookie(cookies[0])
	me := httptest.NewRecorder()
	f.handler.ServeHTTP(me, req)

	if me.Code != http.StatusOK {
		t.Fatalf("GET /v1/me with the redeemed cookie = %d, want 200; body: %s", me.Code, me.Body)
	}
	var caller userResponse
	if err := json.Unmarshal(me.Body.Bytes(), &caller); err != nil {
		t.Fatalf("the /v1/me body is not JSON: %v", err)
	}
	if caller.ID != who.id.String() {
		t.Errorf("the session belongs to %s, want the link's subject %s", caller.ID, who.id)
	}
}

// TestASecondPresentationOfOneLinkIsRefusedOverHTTP is the single-use property at the
// wire, which is where a client discovers it: the first click works and the second
// answers the same 404 a link that never existed gets.
func TestASecondPresentationOfOneLinkIsRefusedOverHTTP(t *testing.T) {
	f := newRedeemFixture(t)
	token := f.mint(t, f.register(t))

	if rec := f.redeem(t, token); rec.Code != http.StatusOK {
		t.Fatalf("the first redemption = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	second := f.redeem(t, token)

	if second.Code != http.StatusNotFound {
		t.Fatalf("the second redemption = %d, want 404; body: %s", second.Code, second.Body)
	}
	if got := decodeProblem(t, second).Code; got != CodeNotFound {
		t.Errorf("code = %q, want %q", got, CodeNotFound)
	}
}

// TestARefusedRedemptionSpendsNothingOverHTTP is identity-disabled-01's argument
// applied to this route, read back out of the TABLE rather than out of the response.
//
// The claim has two halves and the second is the one that makes it worth anything:
// un-disabling restores the flow the operator interrupted. Without it, a link that
// stayed live would be indistinguishable from one quietly invalidated by a refusal.
func TestARefusedRedemptionSpendsNothingOverHTTP(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)
	token := f.mint(t, who)

	f.setDisabled(t, who, true)
	if rec := f.redeem(t, token); rec.Code != http.StatusNotFound {
		t.Fatalf("a disabled subject's link = %d, want 404; body: %s", rec.Code, rec.Body)
	}
	if spent := f.spent(t, who); spent != nil {
		t.Errorf("token_consumed_at = %s after a refused redemption, want NULL", spent)
	}

	f.setDisabled(t, who, false)
	if rec := f.redeem(t, token); rec.Code != http.StatusOK {
		t.Errorf("the same link after re-enabling = %d, want 200. The refusal spent it, so "+
			"re-enabling does not restore the flow the operator interrupted; body: %s",
			rec.Code, rec.Body)
	}
}

// TestALinkMintedBeforeAnEnrollmentRedeemsNothing is the race at the wire, with the
// enrollment done through the REAL flow.
//
// THERE IS NO SEAM HERE AND NO BOOLEAN: the subject really has a confirmed
// `mfa_credentials` row, written by `mfa.Service.Confirm`, moments after the link was
// minted. The login assertion above it is the negative control that makes the test
// mean what it says — if `POST /v1/session` answered 200 for this subject, the second
// factor would not be the one the redemption is racing and the whole test would be
// about nothing.
//
// If this passes against a redemption that trusts the mint, then the mint is the only
// thing standing between a delegated link and a login that skips MFA — and the mint
// was asked minutes before the second factor existed.
func TestALinkMintedBeforeAnEnrollmentRedeemsNothing(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	token := f.mint(t, who)
	enrollMFA(t, f.mfa, who.id, f.clk.Now())

	// THE NEGATIVE CONTROL. The subject's second factor is real, and this service says
	// so to anybody who brings the password.
	login := post(t, f.handler, "/v1/session",
		`{"email":"`+who.email+`","password":"`+who.password+`"}`)
	if login.Code != http.StatusAccepted {
		t.Fatalf("POST /v1/session for an enrolled subject = %d, want 202 — a challenge. If this "+
			"is a 200 the second factor is not the one the redemption is racing; body: %s",
			login.Code, login.Body)
	}

	rec := f.redeem(t, token)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a link minted before the enrollment = %d, want 404. A link that redeems into a "+
			"session for a subject with a second factor is a first factor turning into a complete "+
			"login; body: %s", rec.Code, rec.Body)
	}
	if spent := f.spent(t, who); spent != nil {
		t.Errorf("token_consumed_at = %s after a refused redemption, want NULL: the enrollment is "+
			"something the subject may undo, and spending the link here would leave them unable to "+
			"get in if they did", spent)
	}
}
