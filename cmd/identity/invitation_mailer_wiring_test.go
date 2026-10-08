package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cafaye/identity/internal/accounts"
	"github.com/cafaye/identity/internal/config"
)

// TestBuildInvitationMailerNoCourierStaysNilAcrossTheInterfaceBoundary is the
// regression test for the 2026-10-08 Parlor E2E panic (trace
// f79bef2e-a8eb-40c9-9662-5646445a6f8a): POST /v1/accounts/:id/invitations
// answered 500 with "invalid memory address or nil pointer dereference" on a
// stack with no Courier/mail environment.
//
// The call chain is buildInvitationMailer -> buildAuth -> accounts.NewService
// -> Service.Invite. buildInvitationMailer returned *courier.InvitationMailer,
// nil when Courier is disabled. buildAuth passed that pointer straight into
// NewService, whose parameter/field is the accounts.InvitationMailer
// interface. A typed nil pointer stored in an interface compares non-nil, so
// Invite's `if s.mailer != nil` guard passed and SendInvitation ran on a nil
// receiver (m.link.render dereferences m), panicking.
//
// internal/accounts' TestInviteWithoutAMailerCreatesTheInvitation passes an
// UNTYPED nil into the same parameter, so its interface stays nil and the
// guard holds — which is why the service test was green while the wired
// process panicked. This test drives the BUILDER's no-Courier result across
// the same interface boundary buildAuth crosses and requires it to stay nil.
func TestBuildInvitationMailerNoCourierStaysNilAcrossTheInterfaceBoundary(t *testing.T) {
	cfg, err := config.Load(lookupFrom(envWithSignupKey(map[string]string{})))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.CourierEnabled() {
		t.Fatal("the empty environment reports a mail path, so this is not the no-Courier case")
	}

	built, err := buildInvitationMailer(cfg, slog.New(slog.NewTextHandler(&strings.Builder{}, nil)))
	if err != nil {
		t.Fatalf("buildInvitationMailer: %v", err)
	}

	// THE SAME ASSIGNMENT buildAuth performs: the builder's result into the
	// interface accounts.NewService takes. A typed nil pointer lands here as
	// a non-nil interface and defeats Invite's nil guard.
	var mailer accounts.InvitationMailer = built
	if mailer != nil {
		t.Fatalf("buildInvitationMailer's no-Courier result is %T, which is non-nil as an "+
			"accounts.InvitationMailer — Invite's `s.mailer != nil` guard passes and "+
			"SendInvitation runs on a nil receiver", built)
	}

	// Narrow the failure to the typed-nil shape: the builder must hand back
	// nothing here, not a refusing implementation and not a stub. A non-nil
	// mailer that cannot send would turn a supported state (201 with a token
	// the admin hands over) into a 500 or a dropped mail.
}
