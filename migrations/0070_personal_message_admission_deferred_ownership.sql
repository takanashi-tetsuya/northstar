-- Personal-history admission rows and their archive projections are written
-- in one transaction.  The admission row is deliberately inserted first so
-- an exact replay can return without creating replacement archive rows.
-- Ownership therefore has to be checked at COMMIT, after new archive rows
-- have been inserted, rather than at the admission INSERT statement.

ALTER TABLE personal_message_admissions
    ALTER CONSTRAINT personal_message_admissions_sender_archive_fk
        DEFERRABLE INITIALLY DEFERRED,
    ALTER CONSTRAINT personal_message_admissions_recipient_archive_fk
        DEFERRABLE INITIALLY DEFERRED;
