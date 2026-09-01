ALTER TABLE vcards
ADD COLUMN IF NOT EXISTS avatar_hash VARCHAR(40);

ALTER TABLE vcards
ADD CONSTRAINT vcards_avatar_hash_valid
CHECK (avatar_hash IS NULL OR avatar_hash ~ '^[0-9a-f]{40}$');
