

ALTER TABLE agents DROP CONSTRAINT agents_status_and_claim_agree;

ALTER TABLE agents ADD CONSTRAINT agents_status_and_claim_agree
    CHECK (
        (status = 'unclaimed')
            = (claimed_by_account_id IS NULL
               AND claim_token_digest IS NOT NULL
               AND claim_link_expires_at IS NOT NULL)
        AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
    );


ALTER TABLE agents DROP CONSTRAINT agents_status_and_claim_agree;

ALTER TABLE agents ADD CONSTRAINT agents_status_and_claim_agree
    CHECK (
        (status = 'unclaimed')
            = (claimed_by_account_id IS NULL AND claim_token_digest IS NULL)
        AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
    );
