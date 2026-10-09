-- 00032_agents_claim_link_agree.sql — the one CHECK in 00031 that its own header
-- contradicts.
--
-- THE DEFECT, FOUND BY THE STORE'S FIRST TEST. `agents_status_and_claim_agree`
-- was written
--
--     (status = 'unclaimed')
--         = (claimed_by_account_id IS NULL AND claim_token_digest IS NULL)
--
-- which says an unclaimed agent has NO claim link. The header directly above it
-- says the opposite, and so does every other constraint on the table:
--
--     --   unclaimed  →  no account, no instant, and a LIVE CLAIM LINK
--     CONSTRAINT agents_unclaimed_has_a_live_link
--         CHECK (status <> 'unclaimed' OR
--                (claim_token_digest IS NOT NULL AND claim_link_expires_at IS NOT NULL))
--
-- The two were mutually exclusive, so every registration the service could
-- produce was refused by the database with
-- `new row for relation "agents" violates check constraint
-- agents_status_and_claim_agree"`, and no row could exist at all. The bug was
-- invisible until something INSERTed: the migration applied cleanly, the enum and
-- the CHECKs were all syntactically valid, and `internal/agents`'s first commit
-- had no store to write a row with. The store's first insertion is what found it
-- — which is the argument for the store landing before any route does.
--
-- WHY THIS IS A NEW FILE AND NOT AN EDIT TO 00031. migrations/README.md's rule:
-- no edits to an applied migration. 00031 is applied on every database this
-- branch has touched, and a constraint corrected in place would leave those
-- databases carrying a checksum goose never re-verified while the file on disk
-- disagreed with them. A follow-up is honest about the correction being a
-- correction, and a reader of `goose status` sees a movement rather than a
-- silent change of history.
--
-- WHAT THE FIXED PREDICATE SAYS. An agent is unclaimed exactly when it has no
-- account AND a live claim link; it is claimed or disabled exactly when it has an
-- account. The link half now agrees with the header, with
-- `agents_unclaimed_has_a_live_link`, and with `agents_claim_link_only_while_unclaimed`
-- (a claimed agent's digest is NULL), and the redundancy with the second of those
-- is deliberate: 00031 states each half on its own so that a failure NAMES which
-- half is wrong, and that property survives the rewrite.
--
-- The second conjunct — `(status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)`
-- — is unchanged, because it was never the broken half.
--
-- WHY THE REPLACEMENT IS VALID RATHER THAN NOT VALID: the table is new in this
-- wave, holds no rows anywhere, and there is no historical state to re-check. A
-- NOT VALID constraint would be a promise about rows that do not exist, enforced
-- from the next insert onwards — the same guarantee one line lower, with the
-- option of skipping work nobody needs to skip.

-- +goose Up

ALTER TABLE agents DROP CONSTRAINT agents_status_and_claim_agree;

ALTER TABLE agents ADD CONSTRAINT agents_status_and_claim_agree
    CHECK (
        (status = 'unclaimed')
            = (claimed_by_account_id IS NULL
               AND claim_token_digest IS NOT NULL
               AND claim_link_expires_at IS NOT NULL)
        AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
    );

-- +goose Down

-- The original, defective form. Restoring it makes every registration impossible
-- rather than illegal, which is a strictly more conservative state than the
-- table being right — and it is written back EXACTLY as 00031 had it, so a
-- rollback returns the schema to a state whose defect is already documented
-- rather than to a third variant nobody has read.
ALTER TABLE agents DROP CONSTRAINT agents_status_and_claim_agree;

ALTER TABLE agents ADD CONSTRAINT agents_status_and_claim_agree
    CHECK (
        (status = 'unclaimed')
            = (claimed_by_account_id IS NULL AND claim_token_digest IS NULL)
        AND (status <> 'unclaimed') = (claimed_by_account_id IS NOT NULL)
    );
