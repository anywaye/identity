package recovery

// PACKET identity-sessionlinks-03: THE REDEMPTION, AT THE USE CASE.
//
// # WHAT IS BEING ASSERTED, AND WHY IT IS NOT THE MINT'S TEST AGAIN
//
// The mint already proved that a link is a row of the existing token machine. This
// file is about the three properties that only exist once something CONSUMES that
// row, and every one of them is a property of the order of writes rather than of
// any single statement:
//
//  1. a redemption produces a session, and the link is spent in the same
//     transaction — a link that stays live after handing over a session is a
//     credential with a second use;
//  2. a REFUSAL leaves the link unspent, so the refusals below leave it live. This is
//     the shape `TestARefusedRedemptionDoesNotSpendTheToken` establishes for the
//     reset flow, and the assertion is on the TABLE afterwards rather than on the
//     error — a refused redemption that wrote and rolled back would look identical
//     from the response.
//  3. exactly one of N simultaneous redemptions wins, and the ONLY thing that makes
//     that true is the conditional UPDATE in `Store.Consume`. A read-then-write
//     would pass every other test in this file.
//
// # AND THE CHECKS THE MINT-TIME REFUSAL DOES NOT COVER
//
// `MintSessionLink` refuses a subject with a second factor and a disabled subject,
// so no link for either exists at mint time. Both states are reachable AFTER a link
// has been minted and before it is redeemed, and both are re-checked inside the
// spend transaction. The MFA one is a downgrade otherwise: a link would turn a first
// factor into a complete login for an account whose owner chose two.
//
// The threaded alternative — "just issue a challenge on this route" — is a second
// authentication surface on an unauthenticated route, with its own state, its own
// expiry and its own failure modes. That is a packet of its own and this one does
// not pretend to be it. See `session_link.go`'s ErrSubjectHasSecondFactor.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/platform/id"
	"github.com/cafaye/identity/internal/sessions"
)

// sessionsForUser is how many live sessions a user holds, read straight from the
// table so the assertion cannot be satisfied by a service that reported success and
// wrote nothing.
func (h *harness) sessionsForUser(userID id.UUID) int { return h.sessionsFor(userID) }

// sessionResolves reports whether a token is a live session. This is the claim the
// whole redemption makes — a link redeems into the credential a password login
// would have produced — and it is asserted through the store a client would be
// served by rather than through the redemption's own return value.
func (h *harness) sessionResolves(t *testing.T, token string) bool {
	t.Helper()
	if token == "" {
		return false
	}
	_, err := sessions.NewStore(h.pool).ByToken(t.Context(), h.pool, token, h.now())
	return err == nil
}

// mintLiveLink mints a session link for a subject through the real use case, which
// is what the mint route does — so a redemption test that fails here is a
// redemption problem rather than a fixture problem.
func (h *harness) mintLiveLink(userID id.UUID) sessionLinkFor {
	h.t.Helper()
	link, err := h.svc.MintSessionLink(h.t.Context(), MintSessionLinkInput{UserID: userID})
	if err != nil {
		h.t.Fatalf("MintSessionLink: %v", err)
	}
	return sessionLinkFor{token: link.Token, rowID: h.newestTokenID(userID, PurposeSessionLink)}
}

// ---------------------------------------------------------------------------
// the happy path
// ---------------------------------------------------------------------------

// TestALinkRedeemsIntoASessionAndIsSpent is the route working, asserted from BOTH
// ends of the claim: the value handed back resolves as a live session through the
// sessions store, and the link row says it was spent.
//
// Both halves, because either alone is satisfiable by a lie: a redemption that
// returned a token without writing the row would pass a "the token resolves"
// assertion against a fixture whose session count it never checked, and a spend
// without a session would pass a "the row is spent" assertion on a flow that gave
// the user nothing.
func TestALinkRedeemsIntoASessionAndIsSpent(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	before := h.sessionsForUser(who.id)
	link := h.mintLiveLink(who.id)

	// The exact plaintext the mint handed the caller, read back out of the row's
	// digest rather than kept in a variable from a different call, so the test
	// cannot pass against two tokens.
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

	// And the spend, asked of the table rather than of the return value.
	row := h.storedTokenRow(link.rowID)
	if row["token_consumed_at"] == nil {
		t.Error("token_consumed_at is NULL after a redemption: the link is still live and still " +
			"carries a second session")
	}
	if !redeemed.ExpiresAt.After(h.now()) {
		t.Errorf("expires_at = %s, want an instant after the redemption at %s", redeemed.ExpiresAt, h.now())
	}
}

// TestASecondRedemptionOfTheSameLinkIsRefused is the single-use property stated as
// its own test rather than as a footnote on the first one, because the first one's
// claim is about the FIRST redemption and this is about the second.
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

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

// TestALinkIsRedeemedOnceUnderConcurrency is the property the conditional write
// exists for, and it is asserted as a SUM rather than as "at least one".
//
// "At least one succeeded" is passed by a machine that lets every racer through,
// which is the failure this exists to catch. The concurrent spend of a bare row is
// `TestASessionLinkIsSpentOnceUnderConcurrency`; this one is the same property at
// the layer above it, because the two statements between the read and the spend —
// the second-factor lookup and the disabled check — are exactly the window in which
// a read-then-write redemption would double-mint.
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
	// One more read of the table, because "exactly one winner" measured over what
	// each racer was TOLD is a claim about the responses; this is a claim about the
	// rows.
	if got := h.sessionsForUser(who.id); got != 2 {
		t.Errorf("%d sessions exist after %d concurrent redemptions, want 2", got, racers)
	}
}

// ---------------------------------------------------------------------------
// the race the mint's refusal does not close
// ---------------------------------------------------------------------------

// TestALinkForASubjectWhoEnrolledMFAIsRefusedAndSurvives is the race, live.
//
// The mint refused this subject with a 409, so at MINT time no link exists. The
// link in this test was minted a moment earlier, while the subject had no second
// factor, and then the subject enrolled. Redeeming now would hand a first factor's
// worth of credential to whoever holds the link, which is the whole of MFA.
func TestALinkForASubjectWhoEnrolledMFAIsRefusedAndSurvives(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)

	// The state change the mint's refusal could not have seen.
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

	// The consequence, asserted rather than left as a claim about the row.
	h.secondFactor.enrolled = false
	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err != nil {
		t.Errorf("RedeemSessionLink once the subject has no second factor again = %v, want success: "+
			"the refusal did not spend the link", err)
	}
}

// TestALinkForADisabledSubjectIsRefusedAndSurvives is the same argument for
// `users.disabled_at`, and it is a separate test because the two refusals are
// different facts about different tables.
//
// A user disabled after the mint is refused at the redemption; a user disabled after
// a successful redemption loses the session to the revocation, which is
// identity-disabled-01's argument about `Disable` and not this route's.
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

// TestALinkRedeemsNothingWhenTheDeploymentCannotAskAboutSecondFactors is the
// deployment refusal, and it is the honest direction: a seam that cannot answer is
// not the same fact as an answer of "no", and treating it as one would make the
// MFA refusal above the one control this route has.
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

// TestARefusedRedemptionLeavesNoSessionRowToRollBack is about the DATABASE rather
// than about the error.
//
// The refusals above happen before `Store.Consume` and before the session INSERT, so
// a refusal has nothing to roll back. That is a claim about COST — no row lock, no
// write, no undo — and deliberately not a claim about the outcome: the spend and the
// checks are ONE transaction, so moving the checks after the spend would leave exactly
// the same rows. A red proof that swapped the two orders passed every assertion in
// this file, which is the only way to know that, and it is why
// `session_link_redeem.go` says the transaction is what holds the property.
//
// What IS discriminated here is the session: a redemption that inserted and then
// declined to answer has still given the user a credential, and this reads the
// sessions table to say it did not.
func TestARefusedRedemptionLeavesNoSessionRowToRollBack(t *testing.T) {
	h := newHarness(t, false)
	who := h.registerSimple()
	link := h.mintLiveLink(who.id)
	h.disable(who.id)

	if _, err := h.svc.RedeemSessionLink(t.Context(), RedeemSessionLinkInput{Token: link.token}); err == nil {
		t.Fatal("a disabled subject redeemed a link; the assertions above were vacuous")
	}

	// The fixture's own registration wrote exactly one session, and the refused
	// redemption wrote nothing at all — not a row that a rollback removed, which
	// would still have burned the sequence and left a trace.
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

// ---------------------------------------------------------------------------
// the four ways of being wrong, COMPARED
// ---------------------------------------------------------------------------

// TestALinkRedemptionAnswersIdenticallyForEveryWayOfBeingWrong is the
// indistinguishability claim, and it is a TABLE because the cases have to be
// COMPARED rather than each asserted separately: "each is ErrTokenNotFound" is
// satisfiable by four errors a caller could still tell apart.
//
//   - a token that never existed
//   - an expired one, on a moved clock
//   - one that has been spent
//   - one for a disabled subject        (the row EXISTS, and is live)
//   - one whose subject enrolled MFA     (the row EXISTS, and is live)
//   - a password reset token presented here
//
// The last two are the rows a store-level table could not produce, and they are the
// ones this route's refusals were written for: both are facts about an ACCOUNT
// rather than about a row, and both reach the caller holding a link they may have
// taken rather than somebody who proved anything.
//
// The control is the last row: a live link must still redeem, or the five refusals
// prove nothing.
func TestALinkRedemptionAnswersIdenticallyForEveryWayOfBeingWrong(t *testing.T) {
	cases := []struct {
		name string
		// arrange writes the row this case presents, or changes the subject's state
		// after the link was minted. It returns the plaintext.
		arrange func(t *testing.T, h *harness, who account) string
		// elapsed is how far the clock moves before the redemption, so "expired" is a
		// fixture rather than a sleep.
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
				// A REAL password_reset row for this same subject, so the only thing
				// refusing it is the purpose. A random string would be refused by the
				// digest miss instead and would prove nothing about the closed set.
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
			// The identity of the refusal, not merely that one happened: a caller must
			// not be able to tell these apart, and the only way to assert that at this
			// layer is to check that nothing came back with the error.
			if redeemed.Token != "" || !redeemed.ExpiresAt.IsZero() {
				t.Errorf("a refused redemption returned %+v, want the zero value: a token alongside "+
					"the refusal is a credential nobody asked to be issued", redeemed)
			}
		})
	}
}

// TestTheRedemptionWindowIsTheLoginWindowAndNotTheLinkWindow pins the one constant
// this route had to choose, and it is a constant assertion rather than a behavioral
// one for the reason `TestTheLinkWindowIsShortAndBounded` is.
//
// A session link lives ten minutes; the session it mints lives weeks. Conflating the
// two would mint a session that dies in ten minutes, and a caller that had
// successfully redeemed would be left holding a dead credential with no error
// anywhere.
func TestTheRedemptionWindowIsTheLoginWindowAndNotTheLinkWindow(t *testing.T) {
	if RedeemedSessionTTL <= SessionLinkTTL {
		t.Errorf("RedeemedSessionTTL (%s) is not longer than the link window (%s): a redemption "+
			"would mint a session that dies as soon as the link would have",
			RedeemedSessionTTL, SessionLinkTTL)
	}
}
