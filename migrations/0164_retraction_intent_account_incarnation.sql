-- A local retraction's replay window belongs to the sender account, not to
-- the next account that uses its name. Drain old writers before migration:
-- their address-only conflict target no longer applies to local intents.
ALTER TABLE personal_retraction_intents
    ADD COLUMN sender_account_id UUID REFERENCES users(id) ON DELETE CASCADE;

-- An outbound owner, or an owner distinct from the recorded recipient, is
-- authoritative sender evidence. Never infer a local sender just from the
-- address or assume that retained owner commitments can be decoded. Rows with
-- insufficient surviving evidence remain address-scoped until expiry.
WITH sender_candidates AS (
    SELECT intent.id, account.id AS account_id
      FROM personal_retraction_intents intent
      JOIN personal_retraction_action_projections projection ON projection.intent_id = intent.id
      JOIN users account ON account.id = projection.owner_id
      LEFT JOIN message_archive archive
        ON archive.id = projection.archive_id AND archive.owner_id = projection.owner_id
      LEFT JOIN offline_messages delivery ON delivery.id = intent.c2s_delivery_id
     WHERE account.username = split_part(intent.sender_bare_jid, '@', 1)
       AND (intent.outbound_requested
            OR archive.peer_jid <> intent.sender_bare_jid
            OR delivery.recipient_id <> projection.owner_id)
), unambiguous AS (
    SELECT id, account_id FROM sender_candidates
    WHERE id IN (SELECT id FROM sender_candidates GROUP BY id HAVING count(*) = 1)
)
UPDATE personal_retraction_intents AS intent
   SET sender_account_id = sender.account_id
  FROM unambiguous sender
 WHERE sender.id = intent.id;

DROP INDEX personal_retraction_intent_identity_key;

CREATE UNIQUE INDEX personal_retraction_intent_local_identity_key
    ON personal_retraction_intents(sender_account_id, action_digest)
    WHERE sender_account_id IS NOT NULL;

CREATE UNIQUE INDEX personal_retraction_intent_address_identity_key
    ON personal_retraction_intents(sender_bare_jid, action_digest)
    WHERE sender_account_id IS NULL;
