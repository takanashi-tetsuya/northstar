-- Keep the database-side operation journal credential guard exactly aligned
-- with `src/db/api_operations.rs`.  The application already rejected these
-- names, but the original defence-in-depth function covered only a subset,
-- allowing a direct SQL writer to persist values such as `api_key` or
-- `refresh_token` in an operator-visible durable payload/result.

CREATE OR REPLACE FUNCTION api_json_contains_secret_key(document JSONB)
RETURNS BOOLEAN AS $$
DECLARE
    entry RECORD;
    normalized TEXT;
BEGIN
    IF jsonb_typeof(document) = 'object' THEN
        FOR entry IN SELECT key,value FROM jsonb_each(document) LOOP
            normalized := replace(lower(entry.key),'-','_');
            IF strpos(normalized,'password') > 0
               OR strpos(normalized,'passwd') > 0
               OR strpos(normalized,'passphrase') > 0
               OR strpos(normalized,'secret') > 0
               OR strpos(normalized,'private_key') > 0
               OR strpos(normalized,'api_key') > 0
               OR strpos(normalized,'apikey') > 0
               OR strpos(normalized,'access_token') > 0
               OR strpos(normalized,'refresh_token') > 0
               OR strpos(normalized,'session_token') > 0
               OR strpos(normalized,'client_secret') > 0
               OR strpos(normalized,'bearer') > 0
               OR normalized IN (
                    'token','authorization','cookie','set_cookie'
               )
               OR api_json_contains_secret_key(entry.value)
            THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(document) = 'array' THEN
        FOR entry IN SELECT value FROM jsonb_array_elements(document) LOOP
            IF api_json_contains_secret_key(entry.value) THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    END IF;
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE;
