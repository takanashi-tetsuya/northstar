ALTER TABLE users ADD COLUMN scram_sha256_salt BYTEA;
ALTER TABLE users ADD COLUMN scram_sha256_iterations INTEGER;
ALTER TABLE users ADD COLUMN scram_sha256_stored_key BYTEA;
ALTER TABLE users ADD COLUMN scram_sha256_server_key BYTEA;
