package httpapi


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

type linkSubject struct {
	id       id.UUID
	email    string
	password string
}

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

func (f *redeemFixture) mint(t *testing.T, who linkSubject) string {
	t.Helper()

	link, err := f.links.MintSessionLink(t.Context(), recovery.MintSessionLinkInput{UserID: who.id})
	if err != nil {
		t.Fatalf("MintSessionLink: %v", err)
	}
	return link.Token
}

func (f *redeemFixture) redeem(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, f.handler, "/v1/session-links/redeem", `{"token":"`+token+`"}`)
}

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


func TestTheRedeemedSessionIsByteForByteTheSessionAPasswordLoginMints(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	login := post(t, f.handler, "/v1/session",
		`{"email":"`+who.email+`","password":"`+who.password+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("POST /v1/session = %d, want 200; body: %s", login.Code, login.Body)
	}
	var loginSession sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &loginSession); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	redeemed := f.redeem(t, f.mint(t, who))
	if redeemed.Code != http.StatusOK {
		t.Fatalf("POST /v1/session-links/redeem = %d, want 200; body: %s", redeemed.Code, redeemed.Body)
	}
	var linkSession sessionResponse
	if err := json.Unmarshal(redeemed.Body.Bytes(), &linkSession); err != nil {
		t.Fatalf("the redemption body is not JSON: %v", err)
	}

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

	for _, field := range []string{
		"status:", "content-type:", "set-cookie:", "body:", "expires_at:", "other headers:",
	} {
		if !strings.Contains(loginWalk, field) {
			t.Errorf("the walk never rendered %q, so the agreement above is narrower than it "+
				"claims to be:\n%s", field, loginWalk)
		}
	}
}

func TestTheRedeemedSessionLastsExactlyAsLongAsAPasswordLoginMints(t *testing.T) {
	if recovery.RedeemedSessionTTL != auth.DefaultSessionTTL {
		t.Errorf("recovery.RedeemedSessionTTL is %s and auth.DefaultSessionTTL is %s. A link "+
			"redeems into the session a password login would have produced, and a session that "+
			"expires at a different moment from this service's own other route is not that",
			recovery.RedeemedSessionTTL, auth.DefaultSessionTTL)
	}
}

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


func TestARedeemedSessionSignsTheBrowserIn(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	rec := f.redeem(t, f.mint(t, who))
	if rec.Code != http.StatusOK {
		t.Fatalf("redeeming = %d, want 200; body: %s", rec.Code, rec.Body)
	}

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

func TestALinkMintedBeforeAnEnrollmentRedeemsNothing(t *testing.T) {
	f := newRedeemFixture(t)
	who := f.register(t)

	token := f.mint(t, who)
	enrollMFA(t, f.mfa, who.id, f.clk.Now())

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
