# REPORT — identity-w63-bootkey: the one secret a boot cannot go without, in every manifest

**Base commit:** `076d324` (the worktree was cut from identity master at dispatch;
the previous attempt had already committed the red agreement test there).
**Branch:** `worker/identity-w63-bootkey`.
**Outcome:** done — the three manifests carry the key, the agreement test is green,
the gate passes.

## The packet's claims, verified

Every claim in the packet was true at dispatch:

- `internal/config/config.go` — `loadSignupSigningKey` is called last in `Load`;
  absent is `ErrNoSignupSigningKey`, present-but-wrong is `ErrInvalidSignupSigningKey`
  (not base64url, or not exactly 32 bytes). The comment above it says it is "THE ONE
  UNCONDITIONAL SECRET, checked last so that a deployment with several things wrong
  reports the feature blocks first".
- `docker-compose.yml` — the identity service's `environment:` block carried `PORT`,
  `LOG_LEVEL`, `DATABASE_URL`, the OTEL variables and nothing else. No
  `SIGNUP_SIGNING_KEY`.
- `config/deploy.yml` — `env.secret` carried `DATABASE_URL` and
  `KAMAL_REGISTRY_PASSWORD` only.
- `.env` (git-ignored) — every non-comment line is `KIT_*`; no service variable at all.
- No `.env.example` is committed (`git ls-files | grep '^\.env'` → nothing).
- `.github/workflows/ci.yml` — no occurrence of `SIGNUP_SIGNING_KEY` anywhere in
  the file. The boot step ran the real binary with `DATABASE_URL`, `PORT`,
  `LOG_LEVEL` and (for one process) `MFA_ENCRYPTION_KEY`.

So `docker compose up identity` exited at `config.Load`, a Kamal deploy exited at
`config.Load`, and the CI boot job was red. The packet was correctly scoped.

## The ruling, and what was rejected

**Three manifests, three answers, none of them a usable production key.**

1. **Local / compose — a dev default that is obviously a dev default.**
   `docker-compose.yml` supplies
   `SIGNUP_SIGNING_KEY: ${SIGNUP_SIGNING_KEY:-aWRlbnRpdHktZGV2ZWxvcG1lbnQtc2lnbnVwLWtleSE}`
   so `docker compose up` works on a fresh clone with no `.env` editing. The value
   is the base64url of `identity-development-signup-key!` — 32 ASCII bytes, so it
   decodes to exactly 32 bytes and passes the length check (verified:
   `python3 -c "import base64; print(len(base64.urlsafe_b64decode('aWRlbnRpdHktZGV2ZWxvcG1lbnQtc2lnbnVwLWtleSE'+'==')))"`
   → `32`, decoding to `identity-development-signup-key!`). It is not random and
   not secret: it is the same on every dev machine, and anyone who reads the file
   can mint signup timestamps for a stack that carries it — which is what a
   development stack wants, and what a production stack must never do. A deployment
   that wants a different key sets `SIGNUP_SIGNING_KEY` in `.env`; the
   interpolation is the whole of the override.
2. **Production / Kamal — required, operator-supplied, never defaulted.**
   `config/deploy.yml` lists `SIGNUP_SIGNING_KEY` in `env.secret`, read from the
   operator's environment via `.kamal/secrets`. There is no default anywhere on
   this path: a deploy that does not supply it fails at boot, which is the
   behaviour that already exists and is preserved.
3. **CI — a test value.** The boot job generates an ephemeral key per run
   (`head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'`), masks it
   with `::add-mask::`, and prints only its length. CI is not a deployment, and
   the compose file's development default is what a production key must never look
   like.

**Rejected:**

- *A committed production-plausible key.* Anyone could mint signup timestamps for
  every signup form this service serves. The repo's own `signup_wiring_call_test.go`
  says a literal in the binary "would sign nothing" — the same argument applies to
  a literal in a manifest, with the added defect that a manifest is the one place a
  deployment copies from.
- *A placeholder like `changeme`.* It fails the 32-byte length check and turns a
  working dev loop into a confusing startup error. The default must be a literal
  32-byte base64url string, generated once.
- *No default anywhere.* A fresh clone that meets a startup error naming a variable
  it has never heard of is a broken install path. The dev default is what makes
  `docker compose up` work; the label in the comment above it is what keeps it
  honest.
- *The obvious mint command.* `openssl rand -base64 32` emits the standard alphabet
  and one `=` of padding; `base64.RawURLEncoding.DecodeString` rejects both, so a
  correctly-random key pasted from that command fails boot with "it is not
  base64url". The documented command is
  `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`.

The ruling is recorded as D16 in `DECISIONS.md`.

## The changes

- `docker-compose.yml` — the dev default, with a comment block explaining why a
  default exists here when `COURIER_TOKEN` further down has none (a missing
  `COURIER_TOKEN` is a feature that is off; a missing `SIGNUP_SIGNING_KEY` is the
  process refusing to start), why the value is self-evidently dev, and the mint
  command with the reason plain `openssl rand -base64` is wrong.
- `config/deploy.yml` — `SIGNUP_SIGNING_KEY` added to `env.secret`, with a comment
  recording that it is the one secret on the list that is REQUIRED rather than
  feature-gated, and that there is no default on this path deliberately.
- `.github/workflows/ci.yml` — the boot step's three processes all carry an
  ephemeral `SIGNUP_SIGNING_KEY`. The "no MFA key" process still carries it, so a
  boot that failed there would fail for the wrong reason and prove nothing about the
  MFA surface. The key is generated, masked, and printed nowhere.
- `README.md` — a row in the environment/secrets table, naming the shape (base64url,
  exactly 32 bytes), the three manifests' answers, and the mint command with the
  reason plain `openssl rand -base64` is wrong.
- `DECISIONS.md` — D16, the ruling and what was rejected.
- `cmd/identity/compose_boot_test.go` — the agreement test (committed red at
  `076d324`, green with the manifest changes).
- `cmd/identity/mailer_compose_wiring_test.go` — a comment update: the compose
  file now carries the key, so the mailer test overrides it with the shared fixture
  (the mailer's wiring never reads the value).

## The proof: red first, then green

`cmd/identity/compose_boot_test.go` reads the identity service's environment out
of `docker-compose.yml` by indentation (the repo has no YAML dependency behind
`go.mod`), resolves its `${...}` forms the way compose does, and boots the real
`main()` with exactly that — the child's environment is the resolved block and
nothing else, so the key reaches the process from the manifest and from nowhere
else. A hand-written env literal in the test would pass on the day the manifest
breaks, which is exactly the defect this packet exists to close.

**Red run** (at the base commit `076d324`, reproduced in a temporary worktree):

```
=== RUN   TestTheComposeManifestBootsTheBinary
    compose_boot_test.go:130: the child closed its output before "listening" appeared. The child said:
        2026/10/07 12:36:31 ERROR identity exited with an error error="loading configuration: SIGNUP_SIGNING_KEY is not configured"
--- FAIL: TestTheComposeManifestBootsTheBinary (0.01s)
FAIL
```

The child died at `config.Load` naming the variable — the manifest's env was not
an env identity can start in.

**Green run** (with the manifest changes):

```
=== RUN   TestTheComposeManifestBootsTheBinary
--- PASS: TestTheComposeManifestBootsTheBinary (0.43s)
```

The process reaches "listening", `/healthz` answers `200 {"status":"ok"}`
unconditionally, and SIGTERM drains it to a clean exit.

## The existing failure stays honest

`ErrNoSignupSigningKey` is untouched, and its tests in
`internal/config/config_test.go` still assert that a boot without the key fails
naming the variable. The compose dev default makes that failure unreachable *in a
composed dev stack* — which is correct: the default is labelled, overridable via
`.env`, and production gets its key from `.kamal/secrets` where there is no default.
The CI "no MFA key" process carries the signup key so it fails (when it fails) for
the MFA reason, not the signup reason.

## Out of scope, noted for the successor

- `MFA_ENCRYPTION_KEY`, `OAUTH_ENCRYPTION_KEY` and `OIDC_SIGNING_KEY` are the same
  shape and the same problem, but they each gate a *feature* that is allowed to be
  absent. If the fleet ever makes any of them unconditional, it needs the same
  three-manifest ruling and the same agreement test.
- The Helm chart (`chart/`) already handles the key correctly: it is documented as
  required in the secret, loaded via `envFrom`, with no default. No change needed.
