-- Personal-message admission rows retain a bounded copy of the accepted
-- stanza payload for replay/collision verification.  Before this migration
-- their archive IDs were not foreign keys, so account deletion and archive
-- retention could leave message content behind indefinitely.

DELETE FROM personal_message_admissions admission
WHERE (admission.sender_archive_id IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM message_archive archive
          WHERE archive.id = admission.sender_archive_id
      ))
   OR (admission.recipient_archive_id IS NOT NULL AND NOT EXISTS (
          SELECT 1 FROM message_archive archive
          WHERE archive.id = admission.recipient_archive_id
      ));

ALTER TABLE personal_message_admissions
    ADD CONSTRAINT personal_message_admissions_sender_archive_fk
        FOREIGN KEY (sender_archive_id)
        REFERENCES message_archive(id)
        ON DELETE CASCADE,
    ADD CONSTRAINT personal_message_admissions_recipient_archive_fk
        FOREIGN KEY (recipient_archive_id)
        REFERENCES message_archive(id)
        ON DELETE CASCADE;
