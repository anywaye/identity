package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/anywaye/identity/internal/config"
)

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

	mailer := built
	if mailer != nil {
		t.Fatalf("buildInvitationMailer's no-Courier result is %T, which is non-nil as an "+
			"accounts.InvitationMailer — Invite's `s.mailer != nil` guard passes and "+
			"SendInvitation runs on a nil receiver", built)
	}

}
