-- A missing registration control row is authority corruption, not an implicit
-- request to reopen public registration.  The original scalar subquery yielded
-- NULL when the row was absent, and PL/pgSQL treated `IF NULL` as false.
CREATE OR REPLACE FUNCTION northstar_user_register(
    requested_id UUID,
    requested_username TEXT,
    requested_password_hash TEXT,
    requested_sha256_salt BYTEA,
    requested_iterations INTEGER,
    requested_sha256_stored_key BYTEA,
    requested_sha256_server_key BYTEA,
    requested_sha1_salt BYTEA,
    requested_sha1_iterations INTEGER,
    requested_sha1_stored_key BYTEA,
    requested_sha1_server_key BYTEA,
    requested_invitation_hash BYTEA,
    invitation_required BOOLEAN,
    registration_rate_per_hour INTEGER,
    requested_request_id UUID
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT
AS $$
DECLARE
    invitation_consumed BOOLEAN := FALSE;
    registration_is_closed BOOLEAN;
BEGIN
    IF requested_id IS NULL
       OR requested_username IS NULL
       OR octet_length(requested_username) NOT BETWEEN 1 AND 64
       OR registration_rate_per_hour NOT BETWEEN 1 AND 1000000
       OR NOT northstar_user_credentials_valid(
             requested_password_hash,requested_sha256_salt,requested_iterations,
             requested_sha256_stored_key,requested_sha256_server_key,
             requested_sha1_salt,requested_sha1_iterations,
             requested_sha1_stored_key,requested_sha1_server_key
          ) THEN
        RAISE EXCEPTION 'invalid registration command' USING ERRCODE='22023';
    END IF;
    SELECT setting.enabled INTO STRICT registration_is_closed
      FROM admin_runtime_settings setting
     WHERE setting.key='registration_closed'
     FOR SHARE;
    IF registration_is_closed THEN
        RETURN 'closed';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended('northstar:registration-hour',0)
    );
    IF (SELECT pg_catalog.count(*) FROM users
         WHERE created_at >= pg_catalog.now()-INTERVAL '1 hour')
       >= registration_rate_per_hour THEN
        RETURN 'rate_limited';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(requested_username,0)
    );
    IF EXISTS(SELECT 1 FROM users WHERE username=requested_username) THEN
        RETURN 'username_taken';
    END IF;
    IF requested_invitation_hash IS NOT NULL THEN
        IF octet_length(requested_invitation_hash)<>32 THEN
            RETURN 'invitation_rejected';
        END IF;
        PERFORM 1 FROM invitation_tokens
         WHERE token_hash=requested_invitation_hash
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at>pg_catalog.now())
           AND use_count<max_uses
         FOR UPDATE;
        IF NOT FOUND THEN
            RETURN 'invitation_rejected';
        END IF;
    ELSIF invitation_required THEN
        RETURN 'invitation_rejected';
    END IF;
    IF northstar_capacity_acquire('account',requested_id) IS NULL THEN
        RETURN 'capacity_exhausted';
    END IF;
    IF requested_invitation_hash IS NOT NULL THEN
        UPDATE invitation_tokens
           SET use_count=use_count+1
         WHERE token_hash=requested_invitation_hash
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at>pg_catalog.now())
           AND use_count<max_uses;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'locked invitation changed during registration'
              USING ERRCODE='40001';
        END IF;
        invitation_consumed := TRUE;
    END IF;
    INSERT INTO users(
        id,username,password_hash,is_admin,
        scram_sha256_salt,scram_sha256_iterations,
        scram_sha256_stored_key,scram_sha256_server_key,
        scram_sha1_salt,scram_sha1_iterations,
        scram_sha1_stored_key,scram_sha1_server_key
    ) VALUES (
        requested_id,requested_username,requested_password_hash,FALSE,
        requested_sha256_salt,requested_iterations,
        requested_sha256_stored_key,requested_sha256_server_key,
        requested_sha1_salt,requested_sha1_iterations,
        requested_sha1_stored_key,requested_sha1_server_key
    );
    INSERT INTO audit_log(actor_id,action,target,details,request_id)
    VALUES(
        requested_id,'user.register',requested_username,
        pg_catalog.jsonb_build_object('invitation_consumed',invitation_consumed),
        requested_request_id
    );
    RETURN 'created';
END;
$$;

COMMENT ON FUNCTION northstar_user_register(
    UUID,TEXT,TEXT,BYTEA,INTEGER,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,BYTEA,
    BYTEA,BOOLEAN,INTEGER,UUID
) IS 'Registers one account while failing closed when durable registration control state is absent.';

DO $northstar_registration_control_security$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
BEGIN
    IF migration_schema IS NULL THEN
        RAISE EXCEPTION 'registration control migration requires a current schema'
          USING ERRCODE='3F000';
    END IF;
    EXECUTE pg_catalog.format(
        'ALTER FUNCTION %I.northstar_user_register(UUID,TEXT,TEXT,BYTEA,INTEGER,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,BYTEA,BYTEA,BOOLEAN,INTEGER,UUID) SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
        migration_schema,migration_schema
    );
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %I.northstar_user_register(UUID,TEXT,TEXT,BYTEA,INTEGER,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,BYTEA,BYTEA,BOOLEAN,INTEGER,UUID) FROM PUBLIC',
        migration_schema
    );
END;
$northstar_registration_control_security$;
