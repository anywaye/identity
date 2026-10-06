# REPORT-identity-spamprotection-01

**Packet:** spam protection on signup
**Branch:** worker/identity-w16-spam
**Date:** 2026-10-06
**Budget:** 1 hour

## What landed

### The honeypot (built)

`POST /v1/users` now refuses a submission that carries a populated `website` field.

The field is the honeypot. The sign-in form is rendered by parlor (DECISIONS.md D10 —
identity renders no HTML), and it carries `website` hidden: a person never sees it and
never types into it. A bot fills every field it finds. A populated value therefore
means the submission did not come from the form.

The check runs in the handler, before `auth.Register` is called. A bot that gets a row
in the database has won, even if the row is later deleted: the address is now taken,
and the 409 of DECISIONS.md D9 is a disclosure a stranger can read. The refusal is a
generic `422 validation_failed` that does not name the field, so a bot cannot tell it
apart from any other validation failure and cannot learn which field is the trap.

The field is accepted by the JSON decoder (so the form can send it empty) but is
deliberately absent from `openapi/v1.yaml`: the schema is the contract for API
clients, and a honeypot that is documented is a honeypot the next bot skips.

**Files:**
- `internal/httpapi/auth.go` — the field, the check, the refusal.
- `internal/httpapi/auth_test.go` — the refusal, the empty-field acceptance, the
  before-the-service ordering.

### The signed timestamp (diagnosed, not built)

The second half of the brief — a timestamp signed with a server secret, rejected if
too old or too new — is **not built**, and the reason is the secret.

#### What the timestamp needs

A signed timestamp is a bearer credential for submitting the form: the form carries
`timestamp` + `signature`, and the server verifies the signature before accepting the
submission. The signature is an HMAC-SHA256 over the timestamp, keyed with a server
secret. Without a secret, there is nothing to verify against, and a forged timestamp
is indistinguishable from a real one.

#### Why no configured secret works

The service's configuration (`internal/config/config.go`) carries four secrets, and
none of them can be reused for this:

| Secret | Present | Why it cannot sign the timestamp |
|---|---|---|
| `OIDC_SIGNING_KEY` | only when OIDC is configured | An RSA private key, purpose-bound to OIDC token signing. Reusing it for an HMAC would be key reuse across purposes, and it is absent on every deployment that is not an OIDC provider — the check would vanish exactly where the provider is not mounted. |
| `MFA_ENCRYPTION_KEY` | only when MFA is configured | 32 bytes, purpose-bound to TOTP secret encryption. Same reuse problem, same conditional presence. |
| `OAUTH_ENCRYPTION_KEY` | only when social login is configured | 32 bytes, purpose-bound to OAuth token encryption. Same reuse problem, same conditional presence. |
| `COURIER_TOKEN` | only when courier is configured | A bearer token for the courier service, not a signing key. |

Reusing any of them would couple spam protection to a feature being enabled, and
would put one secret to two purposes — the anti-pattern this repository's own rules
argue against (a key is granted exactly what it names; a secret is used for the
purpose it was configured for).

#### Why hardcoding is not acceptable

A hardcoded secret is a secret in the source tree. It is in every clone, every fork,
every log of every diff, and every bot that reads the source can forge a valid
timestamp. The brief's constraint is explicit: stop and write the diagnosis rather
than hardcode.

#### What a follow-up packet needs to land it

1. A new environment variable, e.g. `SIGNUP_FORM_KEY` — 32+ bytes, base64url like
   `MFA_ENCRYPTION_KEY`, read once at boot and never logged. Absent is a supported
   state (the honeypot still protects signup); present activates the timestamp check.
2. The form (parlor) renders `timestamp` + `signature` alongside the honeypot, signing
   the timestamp with the same key. **This crosses into parlor**, which this packet
   does not touch.
3. The handler verifies the HMAC in constant time, rejects a timestamp younger than
   ~2 s (a bot submits instantly) and older than ~1 h (a signed timestamp is a bearer
   credential and must expire), and refuses with the same generic `422`.
4. Tests: a forged signature, an instant submission, an expired timestamp, and a
   legitimate delayed submission.

Until then, the honeypot is the protection on signup, and it is a real one: any bot
that fills every field the form presents is refused before a row exists.

## Evidence

### The honeypot fails without the check

With the check commented out, the three refusal subtests go red — a bot gets a 201
and a user row:

```
--- FAIL: TestRegisterHoneypotFieldIsRefusedBeforeTheServiceIsCalled (0.00s)
    --- FAIL: TestRegisterHoneypotFieldIsRefusedBeforeTheServiceIsCalled/a_single_character (0.00s)
        auth_test.go:483: status = 201, want 422; body: {"id":"ab000000-0000-0000-0000-000000000000","email":"kaka@example.com"}
    --- FAIL: TestRegisterHoneypotFieldIsRefusedBeforeTheServiceIsCalled/a_filled_honeypot (0.00s)
        auth_test.go:483: status = 201, want 422; body: {"id":"ab000000-0000-0000-0000-000000000000","email":"kaka@example.com"}
    --- FAIL: TestRegisterHoneypotFieldIsRefusedBeforeTheServiceIsCalled/a_whitespace-only_honeypot (0.00s)
        auth_test.go:483: status = 201, want 422; body: {"id":"ab000000-0000-0000-0000-000000000000","email":"kaka@example.com"}
FAIL
```

Restored, the same tests pass:

```
ok  	github.com/cafaye/identity/internal/httpapi	0.960s
```

### bin/prime

```
ok  	github.com/cafaye/identity/client	3.982s
?   	github.com/cafaye/identity/client/generated	[no test files]
ok  	github.com/cafaye/identity/cmd/identity	2.533s
ok  	github.com/cafaye/identity/internal/accounts	18.153s
ok  	github.com/cafaye/identity/internal/admin	5.366s
ok  	github.com/cafaye/identity/internal/apikeys	14.422s
ok  	github.com/cafaye/identity/internal/auth	12.207s
ok  	github.com/cafaye/identity/internal/config	0.993s
ok  	github.com/cafaye/identity/internal/courier	1.180s
ok  	github.com/cafaye/identity/internal/httpapi	49.835s
ok  	github.com/cafaye/identity/internal/mfa	16.836s
ok  	github.com/cafaye/identity/internal/oauth	4.278s
ok  	github.com/cafaye/identity/internal/oidc	2.019s
ok  	github.com/cafaye/identity/internal/outbox	4.033s
ok  	github.com/cafaye/identity/internal/platform/ci	3.221s
ok  	github.com/cafaye/identity/internal/platform/clock	0.571s
ok  	github.com/cafaye/identity/internal/platform/db	0.645s
?   	github.com/cafaye/identity/internal/platform/dbtest	[no test files]
ok  	github.com/cafaye/identity/internal/platform/id	1.035s
ok  	github.com/cafaye/identity/internal/platform/oauthtest	1.097s
ok  	github.com/cafaye/identity/internal/recovery	15.165s
ok  	github.com/cafaye/identity/internal/sessions	1.165s
ok  	github.com/cafaye/identity/internal/telemetry	0.661s
ok  	github.com/cafaye/identity/internal/tenancy	0.816s
ok  	github.com/cafaye/identity/internal/useraudit	3.594s
ok  	github.com/cafaye/identity/internal/users	0.902s
```

24 packages, 0 failures. The database tier ran against the shared cluster
(`postgres://identity:cafaye@127.0.0.1:15500/identity`).

## Constraints respected

- No existing test was weakened or skipped.
- No other repository was modified.
- The honeypot is verified before any user is created.
- No secret was hardcoded.
