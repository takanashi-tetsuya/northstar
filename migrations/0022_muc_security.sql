-- XEP-0045 password-protected rooms and XEP-0421 pseudonymous occupant IDs.
-- Existing rooms receive an application-generated CSPRNG secret on first load;
-- avoiding pgcrypto here keeps migrations usable on restricted PostgreSQL hosts.
ALTER TABLE muc_rooms
    ADD COLUMN password_hash TEXT,
    ADD COLUMN occupant_id_secret BYTEA,
    ADD CONSTRAINT muc_occupant_id_secret_length
        CHECK (occupant_id_secret IS NULL OR octet_length(occupant_id_secret) = 32);
