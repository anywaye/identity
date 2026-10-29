
-- +goose Up

ALTER TABLE account_invitations
    ALTER COLUMN invited_by DROP NOT NULL;

ALTER TABLE account_invitations
    DROP CONSTRAINT account_invitations_invited_by_fkey;

ALTER TABLE account_invitations
    ADD CONSTRAINT account_invitations_invited_by_fkey
    FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_created_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL;

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revocation_is_whole;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revocation_is_whole
    CHECK (revoked_at IS NOT NULL OR revoked_by IS NULL);

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revoked_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revoked_by_fkey
    FOREIGN KEY (revoked_by) REFERENCES users (id) ON DELETE SET NULL;

-- # AND `api_keys.revoked_by` IS DELIBERATELY NOT HERE
--
-- It is `ON DELETE RESTRICT` too, and it looks like the same case. It is not, and
-- the reason is a coincidence in one line of Go: `apikeys.Store.RevokeAllForMember`
-- sets `revoked_by` to the SAME user its WHERE clause filters `user_id` on. So
-- any row referencing a departing person through `revoked_by` is also referencing
-- them through `api_keys_user_id_fkey … ON DELETE CASCADE`, and PostgreSQL removes
-- it through the cascade before the RESTRICT check can see it. The constraint is
-- unreachable.
--
-- `internal/deletion/deletion_rls_test.go`'s `TestARevokedKeyTheUserHeldGoesWithThem`
-- is what measured that, and it is the test that would fail if a path were ever
-- added where one admin revokes a colleague's key — which would make `revoked_by`
-- differ from `user_id` and bring this constraint to life. A migration that
-- changes a constraint nothing can reach is a migration nobody can test, and its
-- CHECK relaxation would be an untested weakening of a security-adjacent
-- invariant.
--
-- Leaving it RESTRICT is also the safe direction: if that path is added, the
-- deletion fails loudly with SQLSTATE 23503 naming this constraint, and whoever
-- adds it reads this paragraph.

-- +goose Down

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revoked_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revoked_by_fkey
    FOREIGN KEY (revoked_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_revocation_is_whole;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_revocation_is_whole
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL));

ALTER TABLE oidc_clients
    DROP CONSTRAINT oidc_clients_created_by_fkey;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE account_invitations
    DROP CONSTRAINT account_invitations_invited_by_fkey;

ALTER TABLE account_invitations
    ADD CONSTRAINT account_invitations_invited_by_fkey
    FOREIGN KEY (invited_by) REFERENCES users (id) ON DELETE RESTRICT;

ALTER TABLE account_invitations
    ALTER COLUMN invited_by SET NOT NULL;