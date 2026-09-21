CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    credential JSONB NOT NULL CHECK (octet_length(credential::TEXT) <= 16384),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    revision UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials(user_id);

-- Only the public challenge is sent to the browser. Verification state stays
-- in this bounded, shared table and is consumed before signature validation.
CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_generation BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('register','login')),
    session_hash BYTEA,
    state JSONB NOT NULL CHECK (octet_length(state::TEXT) <= 65536),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()+interval '5 minutes',
    CHECK ((kind='register' AND session_hash IS NOT NULL AND octet_length(session_hash)=32)
        OR (kind='login' AND session_hash IS NULL))
);
CREATE INDEX webauthn_challenges_expiry ON webauthn_challenges(expires_at);
CREATE INDEX webauthn_challenges_user ON webauthn_challenges(user_id);

CREATE FUNCTION northstar_passkey_challenge(
    p_user UUID,p_generation BIGINT,p_kind TEXT,p_session BYTEA,p_state JSONB
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $challenge$
DECLARE challenge_id UUID;
BEGIN
    PERFORM 1 FROM users WHERE id=p_user AND auth_generation=p_generation
        AND NOT is_disabled FOR SHARE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF p_kind='register' THEN
        PERFORM 1 FROM api_sessions WHERE user_id=p_user AND token_hash=p_session
            AND expires_at>clock_timestamp() FOR SHARE;
        IF NOT FOUND THEN RETURN NULL; END IF;
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(5645368709120145) THEN RETURN NULL; END IF;
    DELETE FROM webauthn_challenges WHERE expires_at<=clock_timestamp();
    IF (SELECT count(*) FROM webauthn_challenges)>=4096
       OR (SELECT count(*) FROM webauthn_challenges WHERE user_id=p_user)>=4 THEN
        RETURN NULL;
    END IF;
    INSERT INTO webauthn_challenges(user_id,auth_generation,kind,session_hash,state)
        VALUES(p_user,p_generation,p_kind,p_session,p_state) RETURNING id INTO challenge_id;
    RETURN challenge_id;
END;
$challenge$;

CREATE FUNCTION northstar_passkey_consume(p_id UUID,p_kind TEXT,p_session BYTEA)
RETURNS TABLE(user_id UUID,auth_generation BIGINT,state JSONB)
LANGUAGE sql SECURITY DEFINER AS $consume$
    DELETE FROM webauthn_challenges challenge WHERE challenge.id=p_id
        AND challenge.kind=p_kind AND challenge.session_hash IS NOT DISTINCT FROM p_session
        AND challenge.expires_at>clock_timestamp()
        RETURNING challenge.user_id,challenge.auth_generation,challenge.state;
$consume$;

CREATE FUNCTION northstar_passkey_register(
    p_user UUID,p_generation BIGINT,p_session BYTEA,p_credential_id BYTEA,
    p_credential JSONB,p_label TEXT
) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $register$
DECLARE registered UUID;
BEGIN
    PERFORM 1 FROM users WHERE id=p_user AND auth_generation=p_generation
        AND NOT is_disabled FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM 1 FROM api_sessions WHERE user_id=p_user AND token_hash=p_session
        AND expires_at>clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF (SELECT count(*) FROM webauthn_credentials WHERE user_id=p_user)>=10 THEN
        RETURN NULL;
    END IF;
    INSERT INTO webauthn_credentials(user_id,credential_id,credential,label)
        VALUES(p_user,p_credential_id,p_credential,p_label)
        ON CONFLICT (credential_id) DO NOTHING RETURNING id INTO registered;
    IF registered IS NOT NULL THEN
        INSERT INTO audit_log(actor_id,action,target) VALUES(p_user,'user.passkey.add',registered::TEXT);
    END IF;
    RETURN registered;
END;
$register$;

CREATE FUNCTION northstar_passkey_accept(
    p_user UUID,p_generation BIGINT,p_id UUID,p_revision UUID,p_credential JSONB,p_count BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $accept$
BEGIN
    PERFORM 1 FROM users WHERE id=p_user AND auth_generation=p_generation
        AND NOT is_disabled FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE webauthn_credentials SET credential=p_credential,sign_count=p_count,
        revision=gen_random_uuid(),last_used_at=clock_timestamp()
        WHERE id=p_id AND user_id=p_user AND revision=p_revision
          AND ((sign_count=0 AND p_count=0) OR p_count>sign_count);
    RETURN FOUND;
END;
$accept$;

CREATE FUNCTION northstar_passkey_remove(p_user UUID,p_generation BIGINT,p_session BYTEA,p_id UUID)
RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER AS $remove$
DECLARE generation BIGINT;
BEGIN
    PERFORM 1 FROM users WHERE id=p_user AND auth_generation=p_generation
        AND NOT is_disabled FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM 1 FROM api_sessions WHERE user_id=p_user AND token_hash=p_session
        AND expires_at>clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    DELETE FROM webauthn_credentials WHERE id=p_id AND user_id=p_user;
    IF NOT FOUND THEN RETURN NULL; END IF;
    UPDATE users SET auth_generation=auth_generation+1 WHERE id=p_user
        RETURNING auth_generation INTO generation;
    UPDATE fast_tokens SET revoked_at=clock_timestamp() WHERE user_id=p_user AND revoked_at IS NULL;
    DELETE FROM api_sessions WHERE user_id=p_user;
    DELETE FROM webauthn_challenges WHERE user_id=p_user;
    UPDATE sm_resume_sessions SET resumable=FALSE,live_lease_until=clock_timestamp(),
        expires_at=clock_timestamp(),updated_at=clock_timestamp() WHERE user_id=p_user;
    INSERT INTO audit_log(actor_id,action,target) VALUES(p_user,'user.passkey.remove',p_id::TEXT);
    RETURN generation;
END;
$remove$;

DO $harden_passkeys$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_passkey_challenge(uuid,int8,text,bytea,jsonb)',
        'northstar_passkey_consume(uuid,text,bytea)',
        'northstar_passkey_register(uuid,int8,bytea,bytea,jsonb,text)',
        'northstar_passkey_accept(uuid,int8,uuid,uuid,jsonb,int8)',
        'northstar_passkey_remove(uuid,int8,bytea,uuid)'
    ] LOOP
        EXECUTE pg_catalog.format('ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature);
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema);
        EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,routine_signature);
    END LOOP;
    EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.webauthn_credentials FROM PUBLIC',migration_schema);
    EXECUTE pg_catalog.format('REVOKE ALL ON TABLE %I.webauthn_challenges FROM PUBLIC',migration_schema);
END;
$harden_passkeys$;
