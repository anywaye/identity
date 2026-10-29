package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/anywaye/identity/internal/accounts"
	"github.com/anywaye/identity/internal/platform/clock"
	"github.com/anywaye/identity/internal/platform/dbtest"
	"github.com/anywaye/identity/internal/platform/id"
)


type tenancyWorld struct {
	handler http.Handler
	clock   *clock.Fake
}

func newTenancyWorld(t *testing.T) *tenancyWorld {
	t.Helper()
	return newTenancyWorldWithSession(t, 24*time.Hour)
}

func newTenancyWorldWithSession(t *testing.T, sessionTTL time.Duration) *tenancyWorld {
	t.Helper()

	pool := dbtest.Schema(t)
	clk := clock.NewFake(time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC))

	return &tenancyWorld{
		handler: New(nil,
			WithAuth(authServiceWithSessionTTL(pool, clk, sessionTTL)),
			WithTenancy(realTenancy(pool, clk)),
			WithLogger(slogLogger(&recordingHandler{})),
		),
		clock: clk,
	}
}

type signedUp struct {
	token string
	id    id.UUID
	email string
}

func (w *tenancyWorld) signUp(t *testing.T) signedUp {
	t.Helper()

	email := dbtest.UniqueEmail(t)
	rec := post(t, w.handler, "/v1/users", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("registering: %d; body: %s", rec.Code, rec.Body)
	}
	var created userResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("the registration body is not JSON: %v", err)
	}
	parsed, err := id.Parse(created.ID)
	if err != nil {
		t.Fatalf("the service returned an unparseable id: %v", err)
	}

	login := post(t, w.handler, "/v1/session", `{"email":"`+email+`","password":"`+matrixPassword+`"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("signing in: %d; body: %s", login.Code, login.Body)
	}
	var session sessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil {
		t.Fatalf("the login body is not JSON: %v", err)
	}

	return signedUp{token: session.Token, id: parsed, email: email}
}

type tenancyResponse struct {
	code      int
	body      string
	account   accountResponse
	member    membershipResponse
	invite    invitationResponse
	list      []accountListItem
	problem   Problem
	rawHeader http.Header
}

func (w *tenancyWorld) call(t *testing.T, token, method, target, body string) *tenancyResponse {
	t.Helper()

	rec := requestAs(t, w.handler, token, method, target, body)
	out := &tenancyResponse{code: rec.Code, body: rec.Body.String(), rawHeader: rec.Header()}

	switch rec.Code {
	case http.StatusOK, http.StatusCreated:
		switch {
		case strings.HasSuffix(target, "/invitations/accept"):
			out.decode(t, &out.member)
		case strings.HasSuffix(target, "/invitations"):
			out.decode(t, &out.invite)
		case target == "/v1/accounts" && method == http.MethodGet:
			out.decode(t, &out.list)
		case strings.Contains(target, "/members/"):
			out.decode(t, &out.member)
		default:
			out.decode(t, &out.account)
		}
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusConflict, http.StatusGone, http.StatusUnprocessableEntity:
		out.decode(t, &out.problem)
	}
	return out
}

func (r *tenancyResponse) decode(t *testing.T, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.body), into); err != nil {
		t.Fatalf("the body is not the JSON the test expects: %v\n%s", err, r.body)
	}
}

func TestRegistrationProvisionsAPersonalAccount(t *testing.T) {
	w := newTenancyWorld(t)
	user := w.signUp(t)

	listed := w.call(t, user.token, http.MethodGet, "/v1/accounts", "")
	if listed.code != http.StatusOK {
		t.Fatalf("GET /v1/accounts = %d; body: %s", listed.code, listed.body)
	}

	var personal *accountListItem
	for i := range listed.list {
		if listed.list[i].Personal {
			personal = &listed.list[i]
		}
	}
	if personal == nil {
		t.Fatalf("no personal account in the list: %+v", listed.list)
	}
	if want := accounts.PersonalName(user.email); personal.Name != want {
		t.Errorf("the personal account is named %q, want the email local part %q", personal.Name, want)
	}
	if personal.Role != accounts.RoleOwner {
		t.Errorf("the personal account's role is %q, want %q", personal.Role, accounts.RoleOwner)
	}
}

func TestSlugUniquenessIs409(t *testing.T) {
	w := newTenancyWorld(t)
	user := w.signUp(t)

	first := w.call(t, user.token, http.MethodPost, "/v1/accounts", `{"name":"Acme Corp"}`)
	if first.code != http.StatusCreated {
		t.Fatalf("the first create = %d; body: %s", first.code, first.body)
	}
	if first.account.Slug != "acme-corp" {
		t.Errorf("slug = %q, want %q", first.account.Slug, "acme-corp")
	}

	second := w.call(t, user.token, http.MethodPost, "/v1/accounts", `{"name":"acme corp"}`)
	if second.code != http.StatusConflict {
		t.Fatalf("the second create = %d, want 409; body: %s", second.code, second.body)
	}
	if second.problem.Code != CodeConflict {
		t.Errorf("code = %q, want %q", second.problem.Code, CodeConflict)
	}

	list := w.call(t, user.token, http.MethodGet, "/v1/accounts", "")
	seen := 0
	for _, item := range list.list {
		if item.Slug == "acme-corp" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("%d accounts carry the slug acme-corp, want 1: %+v", seen, list.list)
	}
}

func TestInvitationLifecycleOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)

	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Inviting"}`)
	if account.code != http.StatusCreated {
		t.Fatalf("creating the account = %d; body: %s", account.code, account.body)
	}
	path := "/v1/accounts/" + account.account.ID

	invitee := w.signUp(t)
	invited := w.call(t, owner.token, http.MethodPost, path+"/invitations",
		`{"email":"`+invitee.email+`","role":"member"}`)
	if invited.code != http.StatusCreated {
		t.Fatalf("inviting = %d; body: %s", invited.code, invited.body)
	}
	if invited.invite.Token == "" {
		t.Fatal("the 201 carries no token, so the invitation cannot be redeemed")
	}
	if strings.Contains(invited.body, "token_digest") {
		t.Errorf("the invitation response carries the stored digest: %s", invited.body)
	}

	if got := w.call(t, invitee.token, http.MethodGet, path, "").code; got != http.StatusNotFound {
		t.Errorf("the invitee reading the account before accepting = %d, want 404", got)
	}

	accepted := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if accepted.code != http.StatusOK {
		t.Fatalf("accepting = %d; body: %s", accepted.code, accepted.body)
	}
	if accepted.member.Role != accounts.RoleMember {
		t.Errorf("the membership's role is %q, want %q", accepted.member.Role, accounts.RoleMember)
	}
	if accepted.member.AccountID != account.account.ID {
		t.Errorf("the membership is for account %s, want %s", accepted.member.AccountID, account.account.ID)
	}
	if accepted.member.UserID != invitee.id.String() {
		t.Errorf("the membership is for user %s, want %s", accepted.member.UserID, invitee.id)
	}

	read := w.call(t, invitee.token, http.MethodGet, path, "")
	if read.code != http.StatusOK {
		t.Fatalf("the invitee reading the account after accepting = %d; body: %s", read.code, read.body)
	}
	if read.account.Role != accounts.RoleMember {
		t.Errorf("the invitee's role is %q, want %q", read.account.Role, accounts.RoleMember)
	}

	again := w.call(t, owner.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if again.code != http.StatusGone {
		t.Errorf("redeeming a spent token = %d, want 410; body: %s", again.code, again.body)
	}
	if again.problem.Code != CodeGone {
		t.Errorf("code = %q, want %q", again.problem.Code, CodeGone)
	}
}

func TestInvitationExpiryAndBadTokensOverHTTP(t *testing.T) {
	w := newTenancyWorldWithSession(t, 30*24*time.Hour)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Expiring"}`)

	invitee := w.signUp(t)
	invited := w.call(t, owner.token, http.MethodPost,
		"/v1/accounts/"+account.account.ID+"/invitations",
		`{"email":"`+invitee.email+`","role":"member"}`)

	w.clock.Advance(accounts.InvitationTTL - time.Second)
	if got := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`).code; got != http.StatusOK {
		t.Errorf("one second before expiry = %d, want 200", got)
	}

	latecomer := w.signUp(t)
	late := w.call(t, owner.token, http.MethodPost,
		"/v1/accounts/"+account.account.ID+"/invitations",
		`{"email":"`+latecomer.email+`","role":"member"}`)
	if late.code != http.StatusCreated {
		t.Fatalf("the second invitation = %d, want 201; body: %s", late.code, late.body)
	}
	w.clock.Advance(accounts.InvitationTTL + time.Second)

	expired := w.call(t, latecomer.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+late.invite.Token+`"}`)
	if expired.code != http.StatusGone {
		t.Errorf("an expired invitation = %d, want 410; body: %s", expired.code, expired.body)
	}

	fresh := w.signUp(t)
	real := late.invite.Token
	if len(real) < 2 {
		t.Fatalf("the second invitation returned no usable token: %q", real)
	}
	tampered := real[:len(real)-1] + "z"
	_, unknown, err := accounts.NewToken()
	if err != nil {
		t.Fatalf("minting an unknown token: %v", err)
	}

	for name, token := range map[string]string{
		"empty":     "",
		"malformed": "not-a-token",
		"unknown":   unknown,
		"tampered":  tampered,
	} {
		t.Run("a "+name+" token is a 404", func(t *testing.T) {
			got := w.call(t, fresh.token, http.MethodPost, "/v1/invitations/accept",
				`{"token":"`+token+`"}`)
			if got.code != http.StatusNotFound {
				t.Errorf("status = %d, want 404; body: %s", got.code, got.body)
			}
			if got.problem.Code != CodeNotFound {
				t.Errorf("code = %q, want %q", got.problem.Code, CodeNotFound)
			}
		})
	}
}

func TestLastOwnerProtectionOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Sole Owner"}`)
	base := "/v1/accounts/" + account.account.ID

	demote := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+owner.id.String(), `{"role":"member"}`)
	if demote.code != http.StatusUnprocessableEntity {
		t.Errorf("the only owner demoting themselves = %d, want 422; body: %s", demote.code, demote.body)
	}
	if demote.problem.Code != CodeValidationFailed {
		t.Errorf("code = %q, want %q", demote.problem.Code, CodeValidationFailed)
	}

	remove := w.call(t, owner.token, http.MethodDelete, base+"/members/"+owner.id.String(), "")
	if remove.code != http.StatusUnprocessableEntity {
		t.Errorf("the only owner removing themselves = %d, want 422; body: %s", remove.code, remove.body)
	}

	read := w.call(t, owner.token, http.MethodGet, base, "")
	if read.account.Role != accounts.RoleOwner {
		t.Errorf("the owner's role is %q after two refusals, want %q", read.account.Role, accounts.RoleOwner)
	}

	successor := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, successor, accounts.RoleMember)

	promoted := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+successor.id.String(), `{"role":"owner"}`)
	if promoted.code != http.StatusOK {
		t.Fatalf("promoting a member to owner = %d, want 200; body: %s", promoted.code, promoted.body)
	}
	if promoted.member.Role != accounts.RoleOwner {
		t.Errorf("the promoted role is %q, want %q", promoted.member.Role, accounts.RoleOwner)
	}

	stepDown := w.call(t, owner.token, http.MethodPatch,
		base+"/members/"+owner.id.String(), `{"role":"member"}`)
	if stepDown.code != http.StatusOK {
		t.Errorf("one of two owners stepping down = %d, want 200; body: %s", stepDown.code, stepDown.body)
	}
	if stepDown.member.Role != accounts.RoleMember {
		t.Errorf("the new role is %q, want %q", stepDown.member.Role, accounts.RoleMember)
	}

	again := w.call(t, successor.token, http.MethodPatch,
		base+"/members/"+successor.id.String(), `{"role":"admin"}`)
	if again.code != http.StatusUnprocessableEntity {
		t.Errorf("the new sole owner demoting themselves = %d, want 422; body: %s", again.code, again.body)
	}

	removeLast := w.call(t, successor.token, http.MethodDelete,
		base+"/members/"+successor.id.String(), "")
	if removeLast.code != http.StatusUnprocessableEntity {
		t.Errorf("the sole owner removing themselves = %d, want 422; body: %s", removeLast.code, removeLast.body)
	}
}

func TestAdminCannotTouchOwnersOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Hierarchy"}`)
	base := "/v1/accounts/" + account.account.ID

	admin := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, admin, accounts.RoleAdmin)

	removeOwner := w.call(t, admin.token, http.MethodDelete, base+"/members/"+owner.id.String(), "")
	if removeOwner.code != http.StatusForbidden {
		t.Errorf("an admin removing the owner = %d, want 403; body: %s", removeOwner.code, removeOwner.body)
	}
	if removeOwner.problem.Code != CodeForbidden {
		t.Errorf("code = %q, want %q", removeOwner.problem.Code, CodeForbidden)
	}

	if got := w.call(t, owner.token, http.MethodGet, base, ""); got.code != http.StatusOK {
		t.Errorf("the owner lost access after a refused removal: %d", got.code)
	}

	inviteAdmin := w.call(t, admin.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"admin"}`)
	if inviteAdmin.code != http.StatusUnprocessableEntity {
		t.Errorf("an admin inviting an admin = %d, want 422; body: %s", inviteAdmin.code, inviteAdmin.body)
	}

	inviteMember := w.call(t, admin.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"member"}`)
	if inviteMember.code != http.StatusCreated {
		t.Errorf("an admin inviting a member = %d, want 201; body: %s", inviteMember.code, inviteMember.body)
	}

	ownerInvite := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"admin"}`)
	if ownerInvite.code != http.StatusCreated {
		t.Errorf("an owner inviting an admin = %d, want 201; body: %s", ownerInvite.code, ownerInvite.body)
	}

	inviteOwner := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+dbtest.UniqueEmail(t)+`","role":"owner"}`)
	if inviteOwner.code != http.StatusUnprocessableEntity {
		t.Errorf("inviting the owner role = %d, want 422; body: %s", inviteOwner.code, inviteOwner.body)
	}
}

func TestDuplicatePendingInvitationIs409(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"One Invite"}`)
	base := "/v1/accounts/" + account.account.ID
	address := dbtest.UniqueEmail(t)

	if got := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+address+`","role":"member"}`).code; got != http.StatusCreated {
		t.Fatalf("the first invitation = %d, want 201", got)
	}
	second := w.call(t, owner.token, http.MethodPost, base+"/invitations",
		`{"email":"`+strings.ToUpper(address)+`","role":"member"}`)
	if second.code != http.StatusConflict {
		t.Errorf("a second pending invitation = %d, want 409; body: %s", second.code, second.body)
	}
}

func TestRenameOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Before"}`)
	base := "/v1/accounts/" + account.account.ID

	renamed := w.call(t, owner.token, http.MethodPatch, base, `{"name":"After"}`)
	if renamed.code != http.StatusOK {
		t.Fatalf("renaming = %d; body: %s", renamed.code, renamed.body)
	}
	if renamed.account.Name != "After" {
		t.Errorf("name = %q, want %q", renamed.account.Name, "After")
	}
	if renamed.account.Slug != account.account.Slug {
		t.Errorf("slug = %q after a rename, want the original %q — a moving slug breaks every link already sent",
			renamed.account.Slug, account.account.Slug)
	}

	blank := w.call(t, owner.token, http.MethodPatch, base, `{"name":"   "}`)
	if blank.code != http.StatusUnprocessableEntity {
		t.Errorf("renaming to whitespace = %d, want 422; body: %s", blank.code, blank.body)
	}
}

func TestDeleteOverHTTP(t *testing.T) {
	w := newTenancyWorld(t)
	owner := w.signUp(t)
	account := w.call(t, owner.token, http.MethodPost, "/v1/accounts", `{"name":"Temporary"}`)
	base := "/v1/accounts/" + account.account.ID

	member := w.signUp(t)
	inviteAndAcceptOver(t, w, owner, base, member, accounts.RoleMember)

	deleted := w.call(t, owner.token, http.MethodDelete, base, "")
	if deleted.code != http.StatusNoContent {
		t.Fatalf("deleting = %d, want 204; body: %s", deleted.code, deleted.body)
	}
	if body := strings.TrimSpace(deleted.body); body != "" {
		t.Errorf("a 204 carries a body: %q", body)
	}

	if got := w.call(t, owner.token, http.MethodGet, base, "").code; got != http.StatusNotFound {
		t.Errorf("reading a deleted account = %d, want 404", got)
	}
	list := w.call(t, member.token, http.MethodGet, "/v1/accounts", "")
	for _, item := range list.list {
		if item.ID == account.account.ID {
			t.Error("a deleted account is still in a former member's list")
		}
	}
}

func TestAccountListIsScopedToTheCaller(t *testing.T) {
	w := newTenancyWorld(t)
	mine := w.signUp(t)
	theirs := w.signUp(t)

	mineAccount := w.call(t, mine.token, http.MethodPost, "/v1/accounts", `{"name":"Mine"}`)
	theirsAccount := w.call(t, theirs.token, http.MethodPost, "/v1/accounts", `{"name":"Theirs"}`)

	listed := w.call(t, mine.token, http.MethodGet, "/v1/accounts", "")
	if listed.code != http.StatusOK {
		t.Fatalf("listing = %d; body: %s", listed.code, listed.body)
	}
	for _, item := range listed.list {
		if item.ID == theirsAccount.account.ID {
			t.Error("the list contains another user's account")
		}
	}

	found := false
	for _, item := range listed.list {
		if item.ID == mineAccount.account.ID {
			found = true
			if item.Role != accounts.RoleOwner {
				t.Errorf("role = %q for an account the caller created, want %q", item.Role, accounts.RoleOwner)
			}
		}
	}
	if !found {
		t.Errorf("the list does not contain the account the caller created: %+v", listed.list)
	}
}

func inviteAndAcceptOver(t *testing.T, w *tenancyWorld, inviter signedUp, base string, invitee signedUp, role accounts.Role) {
	t.Helper()

	invited := w.call(t, inviter.token, http.MethodPost, base+"/invitations",
		`{"email":"`+invitee.email+`","role":"`+string(role)+`"}`)
	if invited.code != http.StatusCreated {
		t.Fatalf("inviting %s as %s: %d; body: %s", invitee.email, role, invited.code, invited.body)
	}

	accepted := w.call(t, invitee.token, http.MethodPost, "/v1/invitations/accept",
		`{"token":"`+invited.invite.Token+`"}`)
	if accepted.code != http.StatusOK {
		t.Fatalf("%s accepting: %d; body: %s", invitee.email, accepted.code, accepted.body)
	}
	if accepted.member.Role != role {
		t.Errorf("%s joined as %q, want the invited role %q", invitee.email, accepted.member.Role, role)
	}
}
