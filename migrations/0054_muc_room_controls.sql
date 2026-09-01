-- XEP-0045 owner-configurable room behaviour not represented by the original
-- schema.  Existing rooms retain their historical behaviour.
ALTER TABLE muc_rooms
    ADD COLUMN description TEXT,
    ADD COLUMN allow_subject_change BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN allow_invites BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN allow_private_messages BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN logging_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN allow_registration BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE muc_affiliations
    ADD COLUMN reserved_nick VARCHAR(128);

ALTER TABLE muc_external_affiliations
    ADD COLUMN reserved_nick VARCHAR(128);

CREATE UNIQUE INDEX muc_affiliations_reserved_nick_idx
    ON muc_affiliations(room_id, reserved_nick)
    WHERE reserved_nick IS NOT NULL;

CREATE UNIQUE INDEX muc_external_affiliations_reserved_nick_idx
    ON muc_external_affiliations(room_id, reserved_nick)
    WHERE reserved_nick IS NOT NULL;
