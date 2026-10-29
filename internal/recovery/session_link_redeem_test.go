package recovery


import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/platform/id"
	"github.com/anywaye/identity/internal/sessions"
)

func (h *harness) sessionsForUser(userID id.UUID) int { return h.sessionsFor(userID) }

func (h *harness) sessionResolves(t *testing.T, token string) bool {
	t.Helper()
	if token == "" {
		return false
	}
	_, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, token, h.now())
	return err == nil
}

func (h *harness) mintLiveLink(userID id.UUID) sessionLinkFor {
	h.t.Helper()
	link, err := h.svc.MintSessionLink(h.t.Context(), MintSessionLinkInput{UserID: userID})
	if err != nil {
		h.t.Fatalf("MintSessionLink: %v", err)
	}
	return sessionLinkFor{token: link.Token, rowID: h.newestTokenID(userID, PurposeSessionLink)}
}


func TestALinkRedeemsIntoASessionAndIsSpent(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	before := h.sessionsForUser(who.id)
	link := h.mintLiveLink(who.id)

	redeemed, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})
	if err != nil {
		t.Fatalf("RedeemSessionLink = %v, want a session", err)
	}
	if !h.sessionResolves(t, redeemed.Token) {
		t.Fatal("the redeemed token does not resolve as a live session. A link that redeems into " +
			"nothing is the whole failure this route exists to prevent")
	}
	if got := h.sessionsForUser(who.id); got != before+1 {
		t.Errorf("%d sessions exist after the redemption, want %d", got, before+1)
	}

	row := h.storedTokenRow(link.rowID)
	if row["token_consumed_at"] == nil {
		t.Error("token_consumed_at is NULL after a redemption: the link is still live and still " +
			"carries a second session")
	}
	if !redeemed.ExpiresAt.After(h.now()) {
		t.Errorf("expires_at = %s, want an instant after the redemption at %s", redeemed.ExpiresAt, h.now())
	}
}

func TestASecondRedemptionOfTheSameLinkIsRefused(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err != nil {
		t.Fatalf("the first redemption = %v, want a session", err)
	}
	_, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})

	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("the second redemption = %v, want ErrTokenNotFound — the shape of a token that "+
			"never existed, because a link that names its own history tells a holder of a stolen "+
			"link that somebody used it", err)
	}
	if got := h.sessionsForUser(who.id); got != 2 {
		t.Errorf("%d sessions exist after a second redemption was refused, want 2: the refused one "+
			"wrote a row", got)
	}
}


func TestALinkIsRedeemedOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	const racers = 8
	type outcome struct {
		token string
		err   error
	}
	results := make(chan outcome, racers)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			redeemed, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})
			results <- outcome{token: redeemed.Token, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners, losers := 0, 0
	for got := range results {
		switch {
		case got.err == nil:
			winners++
			if !h.sessionResolves(t, got.token) {
				t.Errorf("a racer reported success and its session does not resolve: %v", got.err)
			}
		case errors.Is(got.err, ErrTokenNotFound):
			losers++
		default:
			t.Errorf("a racer got %v, want ErrTokenNotFound for every loser", got.err)
		}
	}

	if winners != 1 {
		t.Errorf("%d of %d concurrent redemptions of one link succeeded, want exactly 1", winners, racers)
	}
	if losers != racers-1 {
		t.Errorf("%d racers were refused, want %d", losers, racers-1)
	}
	if got := h.sessionsForUser(who.id); got != 2 {
		t.Errorf("%d sessions exist after %d concurrent redemptions, want 2", got, racers)
	}
}


func TestALinkForASubjectWhoEnrolledMFAIsRefusedAndSurvives(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	h.secondFactor.enrolled = true

	_, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})

	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("RedeemSessionLink for a subject who enrolled after the mint = %v, want "+
			"ErrTokenNotFound. NOT ErrSubjectHasSecondFactor: on this route the token IS the "+
			"credential, so the caller may be whoever took the link, and an answer naming the "+
			"account's state publishes it to exactly the person the operator acted about",
			err)
	}
	if got := h.sessionsForUser(who.id); got != 1 {
		t.Errorf("%d sessions exist after the refusal, want 1: the refused redemption minted one", got)
	}
	if row := h.storedTokenRow(link.rowID); row["token_consumed_at"] != nil {
		t.Errorf("token_consumed_at = %v after a refused redemption, want NULL — the link stays "+
			"live, so un-enrolling restores the flow the operator interrupted", row["token_consumed_at"])
	}

	h.secondFactor.enrolled = false
	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err != nil {
		t.Errorf("RedeemSessionLink once the subject has no second factor again = %v, want success: "+
			"the refusal did not spend the link", err)
	}
}

func TestALinkForADisabledSubjectIsRefusedAndSurvives(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	h.disable(who.id)

	_, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})

	if !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("RedeemSessionLink for a disabled subject = %v, want ErrTokenNotFound — the shape "+
			"of a token that never existed, for the reason TestALinkForASubjectWhoEnrolledMFAIsRefused"+
			"AndSurvives gives", err)
	}
	if got := h.sessionsForUser(who.id); got != 1 {
		t.Errorf("%d sessions exist after the refusal, want 1", got)
	}
	if row := h.storedTokenRow(link.rowID); row["token_consumed_at"] != nil {
		t.Errorf("token_consumed_at = %v after a refused redemption, want NULL: an operator who "+
			"disabled an account did not also decide to invalidate the link already in flight",
			row["token_consumed_at"])
	}

	h.enable(who.id)
	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err != nil {
		t.Errorf("RedeemSessionLink after re-enabling = %v, want success", err)
	}
}

func TestALinkRedeemsNothingWhenTheDeploymentCannotAskAboutSecondFactors(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	h.secondFactor.err = ErrMFAUnavailable
	_, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token})
	if !errors.Is(err, ErrMFAUnavailable) {
		t.Fatalf("RedeemSessionLink with an unanswerable seam = %v, want ErrMFAUnavailable", err)
	}
	if got := h.sessionsForUser(who.id); got != 1 {
		t.Errorf("%d sessions exist, want 1: an unanswerable deployment minted one anyway", got)
	}
	if row := h.storedTokenRow(link.rowID); row["token_consumed_at"] != nil {
		t.Error("the link was spent by a redemption this deployment could not answer safely")
	}
}

func TestARefusedRedemptionLeavesNoSessionRowToRollBack(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)
	h.disable(who.id)

	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err == nil {
		t.Fatal("a disabled subject redeemed a link; the assertions above were vacuous")
	}

	if got := h.sessionsForUser(who.id); got != 1 {
		t.Errorf("%d sessions exist, want 1", got)
	}
	var ids int
	if err := h.pool.QueryRow(t.Context(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND expires_at > $2`, who.id, h.now()).Scan(&ids); err != nil {
		t.Fatalf("counting sessions: %v", err)
	}
	if ids != 1 {
		t.Errorf("%d unexpired session rows exist, want 1", ids)
	}
}


func TestALinkRedemptionAnswersIdenticallyForEveryWayOfBeingWrong(t *testing.T) {
	cases := []struct {
		name string
		arrange func(t *testing.T, h *harness, who account) string
		elapsed time.Duration
		wantErr bool
	}{
		{
			name: "a token that never existed",
			arrange: func(_ *testing.T, _ *harness, _ account) string {
				token, _, err := sessions.NewToken()
				if err != nil {
					t.Fatalf("NewToken: %v", err)
				}
				return token
			},
			wantErr: true,
		},
		{
			name: "an expired link",
			arrange: func(t *testing.T, h *harness, who account) string {
				return h.mintLiveLink(who.id).token
			},
			elapsed: SessionLinkTTL + time.Second,
			wantErr: true,
		},
		{
			name: "a link that has been spent",
			arrange: func(t *testing.T, h *harness, who account) string {
				link := h.mintLiveLink(who.id)
				if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err != nil {
					t.Fatalf("spending the link in its own fixture: %v", err)
				}
				return link.token
			},
			wantErr: true,
		},
		{
			name: "a link for a disabled subject",
			arrange: func(t *testing.T, h *harness, who account) string {
				link := h.mintLiveLink(who.id)
				h.disable(who.id)
				return link.token
			},
			wantErr: true,
		},
		{
			name: "a link whose subject enrolled a second factor",
			arrange: func(t *testing.T, h *harness, who account) string {
				link := h.mintLiveLink(who.id)
				h.secondFactor.enrolled = true
				return link.token
			},
			wantErr: true,
		},
		{
			name: "a password reset token presented as a link",
			arrange: func(t *testing.T, h *harness, who account) string {
				if err := h.svc.RequestPasswordReset(t.Context(), who.email); err != nil {
					t.Fatalf("RequestPasswordReset: %v", err)
				}
				return tokenFrom(t, h.mailer.last(t))
			},
			wantErr: true,
		},
		{
			name: "CONTROL: a live link",
			arrange: func(_ *testing.T, h *harness, who account) string {
				return h.mintLiveLink(who.id).token
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, false)
			who := h.registerSimple()

			presented := tc.arrange(t, h, who)
			if tc.elapsed > 0 {
				h.clk.Advance(tc.elapsed)
			}

			redeemed, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: presented})

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("RedeemSessionLink on the control row = %v, want a session. Every "+
						"refusal in this table would then be satisfied by an implementation that "+
						"refuses everything", err)
				}
				if !h.sessionResolves(t, redeemed.Token) {
					t.Fatal("the control redemption handed back a token that resolves to nothing")
				}
				return
			}

			if !errors.Is(err, ErrTokenNotFound) {
				t.Fatalf("RedeemSessionLink = %v, want ErrTokenNotFound", err)
			}
			if redeemed.Token != "" || !redeemed.ExpiresAt.IsZero() {
				t.Errorf("a refused redemption returned %+v, want the zero value: a token alongside "+
					"the refusal is a credential nobody asked to be issued", redeemed)
			}
		})
	}
}

func TestTheRedemptionWindowIsTheLoginWindowAndNotTheLinkWindow(t *testing.T) {
	if RedeemedSessionTTL <= SessionLinkTTL {
		t.Errorf("RedeemedSessionTTL (%s) is not longer than the link window (%s): a redemption "+
			"would mint a session that dies as soon as the link would have",
			RedeemedSessionTTL, SessionLinkTTL)
	}
}
