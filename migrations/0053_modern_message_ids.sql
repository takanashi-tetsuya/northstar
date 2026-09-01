-- XEP-0308, XEP-0424, XEP-0444, and XEP-0461 all reference the opaque
-- message ID selected by an endpoint.  Keep the database admission bound in
-- sync with the protocol parser instead of failing an otherwise valid action
-- after delivery has already been accepted.
ALTER TABLE message_archive
    ALTER COLUMN stanza_id TYPE VARCHAR(1024);
