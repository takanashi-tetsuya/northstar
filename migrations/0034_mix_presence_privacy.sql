-- XEP-0403 current presence is transient and is keyed by an encoded stable
-- participant JID.  Older Northstar versions used the publisher's real full
-- JID as item_id, which leaks identity in hidden-JID channels and cannot be
-- trusted after a process restart because the corresponding resource is no
-- longer known to be online.  Presence is therefore deliberately cleared on
-- upgrade; clients republish after reconnect.
DELETE FROM mix_events
WHERE node = 'urn:xmpp:mix:nodes:presence';

-- A standards-compliant encoded full JID may be longer than one JID part.
ALTER TABLE mix_events
    ALTER COLUMN item_id TYPE VARCHAR(4095);

-- In a hidden-JID channel XEP-0403 requires a nickname because no real JID is
-- present in the authoritative identity extension.
UPDATE mix_channels
SET nick_required = TRUE, updated_at = NOW()
WHERE jid_visibility = 'hidden' AND NOT nick_required;
