

ALTER TABLE account_invitations ADD COLUMN revoked_at timestamptz;


DROP INDEX account_invitations_pending_idx;

CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email)
	WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX account_invitations_account_id_idx ON account_invitations (account_id, id);


DROP INDEX account_invitations_account_id_idx;

DROP INDEX account_invitations_pending_idx;
CREATE UNIQUE INDEX account_invitations_pending_idx
	ON account_invitations (account_id, email) WHERE accepted_at IS NULL;

ALTER TABLE account_invitations DROP COLUMN revoked_at;
