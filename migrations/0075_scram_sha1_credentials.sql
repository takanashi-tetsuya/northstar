-- SCRAM-SHA-1 compatibility verifiers are deliberately independent from
-- SCRAM-SHA-256. Existing accounts acquire them on their next successful
-- password authentication or password reset; NULL is never treated as an
-- unknown account when SHA-1 compatibility is enabled.
ALTER TABLE users ADD COLUMN scram_sha1_salt BYTEA;
ALTER TABLE users ADD COLUMN scram_sha1_iterations INTEGER;
ALTER TABLE users ADD COLUMN scram_sha1_stored_key BYTEA;
ALTER TABLE users ADD COLUMN scram_sha1_server_key BYTEA;
