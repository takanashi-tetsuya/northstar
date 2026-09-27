-- A purpose-bound REST TLS reload command for the table-free command login.
-- The application supplies only keyed request digests and an encrypted replay;
-- the bearer itself and plaintext response never enter these routines.

CREATE FUNCTION northstar_admin_tls_reload_admit(
    requested_actor UUID, expected_generation BIGINT, presented_session_hash BYTEA,
    current_scope BYTEA, previous_scope BYTEA,
    current_principal BYTEA, previous_principal BYTEA,
    current_fingerprint BYTEA, previous_fingerprint BYTEA,
    current_key_id TEXT, proposed_request_id UUID,
    requested_lease_seconds BIGINT, requested_ttl_seconds BIGINT
) RETURNS TABLE (
    outcome TEXT, record_id UUID, request_id UUID, lease_token UUID,
    stored_scope_hash BYTEA, stored_fingerprint BYTEA,
    response_status SMALLINT, response_key_id TEXT, response_nonce BYTEA,
    response_ciphertext BYTEA, needs_rotation BOOLEAN, retry_after BIGINT
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_admin_tls_reload_admit$
DECLARE
    capacity_count BIGINT;
    active_count BIGINT;
    matching_count BIGINT;
    stored api_idempotency_records%ROWTYPE;
    now_at TIMESTAMPTZ;
BEGIN
    IF requested_actor IS NULL OR expected_generation IS NULL
       OR presented_session_hash IS NULL OR octet_length(presented_session_hash)<>32
       OR current_scope IS NULL OR octet_length(current_scope)<>32
       OR current_principal IS NULL OR octet_length(current_principal)<>32
       OR current_fingerprint IS NULL OR octet_length(current_fingerprint)<>32
       OR (previous_scope IS NULL)<>(previous_principal IS NULL)
       OR (previous_scope IS NULL)<>(previous_fingerprint IS NULL)
       OR (previous_scope IS NOT NULL AND (
           octet_length(previous_scope)<>32 OR
           octet_length(previous_principal)<>32 OR
           octet_length(previous_fingerprint)<>32))
       OR current_key_id IS NULL OR current_key_id !~ '^[0-9a-f]{16}$'
       OR proposed_request_id IS NULL
       OR requested_lease_seconds IS NULL OR requested_lease_seconds NOT BETWEEN 5 AND 300
       OR requested_ttl_seconds IS NULL OR requested_ttl_seconds NOT BETWEEN 60 AND 86400 THEN
        RAISE EXCEPTION 'invalid TLS reload admission parameters'
          USING ERRCODE='22023';
    END IF;

    -- Keep the user and bearer locks until the caller commits this transaction.
    -- A concurrent disable, password change or logout cannot pass this fence.
    PERFORM 1 FROM users AS actor
     WHERE actor.id=requested_actor AND actor.auth_generation=expected_generation
       AND actor.is_admin AND NOT actor.is_disabled FOR SHARE;
    IF NOT FOUND THEN
        outcome := 'forbidden'; RETURN NEXT; RETURN;
    END IF;
    PERFORM 1 FROM api_sessions AS session
     WHERE session.user_id=requested_actor
       AND session.token_hash=presented_session_hash
       AND session.expires_at>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN
        outcome := 'forbidden'; RETURN NEXT; RETURN;
    END IF;

    -- Match the existing global lock ordering and bounded SKIP LOCKED policy.
    SELECT capacity.active_records INTO capacity_count
      FROM api_idempotency_capacity AS capacity
     WHERE capacity.singleton FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        IF NOT EXISTS (SELECT 1 FROM api_idempotency_capacity WHERE singleton) THEN
            RAISE EXCEPTION 'API idempotency capacity authority row is missing'
              USING ERRCODE='55000';
        END IF;
        outcome := 'busy'; retry_after := 1; RETURN NEXT; RETURN;
    END IF;

    DELETE FROM api_idempotency_records AS reservation
     WHERE reservation.expires_at<=clock_timestamp()
       AND (reservation.scope_hash=current_scope OR
            (previous_scope IS NOT NULL AND reservation.scope_hash=previous_scope));
    DELETE FROM api_idempotency_records AS reservation
     WHERE reservation.state='started' AND reservation.expires_at<=clock_timestamp()
       AND (reservation.principal_hash=current_principal OR
            (previous_principal IS NOT NULL AND reservation.principal_hash=previous_principal));

    SELECT count(*) INTO matching_count FROM api_idempotency_records AS reservation
     WHERE reservation.scope_hash=current_scope OR
           (previous_scope IS NOT NULL AND reservation.scope_hash=previous_scope);
    IF matching_count>1 THEN
        outcome := 'idempotency_conflict'; RETURN NEXT; RETURN;
    END IF;
    IF matching_count=1 THEN
        SELECT reservation.* INTO stored FROM api_idempotency_records AS reservation
         WHERE reservation.scope_hash=current_scope OR
               (previous_scope IS NOT NULL AND reservation.scope_hash=previous_scope)
         FOR UPDATE;
    ELSE
        SELECT count(*) INTO active_count FROM api_idempotency_records AS reservation
         WHERE reservation.state='started' AND reservation.expires_at>clock_timestamp()
           AND (reservation.principal_hash=current_principal OR
                (previous_principal IS NOT NULL AND reservation.principal_hash=previous_principal));
        IF active_count>=32 THEN
            outcome := 'capacity_limited'; retry_after := 30; RETURN NEXT; RETURN;
        END IF;
        SELECT count(*) INTO active_count FROM api_idempotency_records AS reservation
         WHERE reservation.expires_at>clock_timestamp()
           AND (reservation.principal_hash=current_principal OR
                (previous_principal IS NOT NULL AND reservation.principal_hash=previous_principal));
        SELECT capacity.active_records INTO capacity_count
          FROM api_idempotency_capacity AS capacity WHERE capacity.singleton;
        IF active_count>=128 OR capacity_count>=100000 THEN
            outcome := 'capacity_limited'; retry_after := 60; RETURN NEXT; RETURN;
        END IF;
        INSERT INTO api_idempotency_records (
            id,scope_hash,principal_hash,scope_key_id,request_actor_id,
            ownership_actor_id,principal_kind,method,route,request_fingerprint,
            request_id,state,lease_token,lease_expires_at,expires_at
        ) VALUES (
            gen_random_uuid(),current_scope,current_principal,current_key_id,
            requested_actor,requested_actor,'admin','POST','/api/v1/admin/tls/reload',
            current_fingerprint,proposed_request_id,'started',gen_random_uuid(),
            clock_timestamp()+requested_lease_seconds*INTERVAL '1 second',
            clock_timestamp()+LEAST(requested_ttl_seconds,300)*INTERVAL '1 second'
        ) RETURNING * INTO stored;
        outcome := 'acquired'; record_id := stored.id;
        request_id := stored.request_id; lease_token := stored.lease_token;
        stored_scope_hash := stored.scope_hash;
        stored_fingerprint := stored.request_fingerprint;
        RETURN NEXT; RETURN;
    END IF;

    IF (stored.request_fingerprint<>current_fingerprint AND
        (previous_fingerprint IS NULL OR stored.request_fingerprint<>previous_fingerprint))
       OR stored.method<>'POST' OR stored.route<>'/api/v1/admin/tls/reload'
       OR stored.principal_kind<>'admin'
       OR stored.request_actor_id IS DISTINCT FROM requested_actor THEN
        outcome := 'idempotency_conflict'; RETURN NEXT; RETURN;
    END IF;

    record_id := stored.id;
    request_id := stored.request_id;
    stored_scope_hash := stored.scope_hash;
    stored_fingerprint := stored.request_fingerprint;
    needs_rotation := stored.scope_hash<>current_scope
                      OR stored.request_fingerprint<>current_fingerprint;
    IF stored.state='completed' THEN
        IF stored.response_status<>202 OR stored.response_key_id IS NULL
           OR octet_length(stored.response_nonce)<>12
           OR stored.response_ciphertext IS NULL THEN
            RAISE EXCEPTION 'invalid TLS reload replay record'
              USING ERRCODE='55000';
        END IF;
        outcome := 'replay';
        response_status := stored.response_status;
        response_key_id := stored.response_key_id;
        response_nonce := stored.response_nonce;
        response_ciphertext := stored.response_ciphertext;
        RETURN NEXT; RETURN;
    END IF;

    now_at := clock_timestamp();
    IF stored.lease_expires_at>now_at THEN
        outcome := 'in_progress';
        retry_after := GREATEST(1,CEIL(EXTRACT(EPOCH FROM stored.lease_expires_at-now_at)))::BIGINT;
        RETURN NEXT; RETURN;
    END IF;
    UPDATE api_idempotency_records AS reservation
       SET lease_token=gen_random_uuid(),
           lease_expires_at=clock_timestamp()+requested_lease_seconds*INTERVAL '1 second',
           scope_hash=current_scope,principal_hash=current_principal,
           request_fingerprint=current_fingerprint,scope_key_id=current_key_id,
           attempts=reservation.attempts+1,updated_at=clock_timestamp()
     WHERE reservation.id=stored.id AND reservation.state='started'
       AND reservation.lease_expires_at<=clock_timestamp()
       AND reservation.attempts<1000
     RETURNING reservation.lease_token INTO lease_token;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TLS reload lease could not be recovered'
          USING ERRCODE='55000';
    END IF;
    stored_scope_hash := current_scope;
    stored_fingerprint := current_fingerprint;
    needs_rotation := FALSE;
    outcome := 'acquired'; RETURN NEXT;
END;
$northstar_admin_tls_reload_admit$;

CREATE FUNCTION northstar_admin_tls_reload_rekey(
    requested_record UUID, requested_actor UUID, expected_generation BIGINT,
    presented_session_hash BYTEA, old_scope BYTEA, old_fingerprint BYTEA,
    new_scope BYTEA, new_principal BYTEA, new_fingerprint BYTEA,
    new_key_id TEXT, new_nonce BYTEA, new_ciphertext BYTEA
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_admin_tls_reload_rekey$
BEGIN
    IF requested_record IS NULL OR requested_actor IS NULL OR
       expected_generation IS NULL OR presented_session_hash IS NULL OR
       octet_length(presented_session_hash)<>32 OR
       old_scope IS NULL OR octet_length(old_scope)<>32 OR
       old_fingerprint IS NULL OR octet_length(old_fingerprint)<>32 OR
       new_scope IS NULL OR octet_length(new_scope)<>32 OR
       new_principal IS NULL OR octet_length(new_principal)<>32 OR
       new_fingerprint IS NULL OR octet_length(new_fingerprint)<>32 OR
       new_key_id IS NULL OR new_key_id !~ '^[0-9a-f]{16}$' OR
       new_nonce IS NULL OR octet_length(new_nonce)<>12 OR
       new_ciphertext IS NULL OR octet_length(new_ciphertext) NOT BETWEEN 16 AND 1057808 THEN
        RETURN FALSE;
    END IF;
    PERFORM 1 FROM users AS actor
     WHERE actor.id=requested_actor AND actor.auth_generation=expected_generation
       AND actor.is_admin AND NOT actor.is_disabled FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM 1 FROM api_sessions AS session
     WHERE session.user_id=requested_actor
       AND session.token_hash=presented_session_hash
       AND session.expires_at>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    UPDATE api_idempotency_records AS reservation
       SET scope_hash=new_scope,principal_hash=new_principal,
           request_fingerprint=new_fingerprint,scope_key_id=new_key_id,
           response_key_id=new_key_id,response_nonce=new_nonce,
           response_ciphertext=new_ciphertext,updated_at=clock_timestamp()
     WHERE reservation.id=requested_record AND reservation.scope_hash=old_scope
       AND reservation.request_fingerprint=old_fingerprint
       AND reservation.request_actor_id=requested_actor
       AND reservation.principal_kind='admin' AND reservation.method='POST'
       AND reservation.route='/api/v1/admin/tls/reload'
       AND reservation.state='completed' AND reservation.response_status=202;
    RETURN FOUND;
EXCEPTION WHEN unique_violation THEN
    RETURN FALSE;
END;
$northstar_admin_tls_reload_rekey$;

CREATE FUNCTION northstar_admin_tls_reload_commit(
    requested_record UUID, requested_lease UUID,
    requested_actor UUID, expected_generation BIGINT,
    presented_session_hash BYTEA, requested_operation UUID,
    replay_key_id TEXT, replay_nonce BYTEA, replay_ciphertext BYTEA,
    requested_ttl_seconds BIGINT
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
AS $northstar_admin_tls_reload_commit$
DECLARE
    reservation api_idempotency_records%ROWTYPE;
BEGIN
    IF requested_record IS NULL OR requested_lease IS NULL OR
       requested_actor IS NULL OR requested_operation IS NULL OR
       expected_generation IS NULL OR presented_session_hash IS NULL OR
       octet_length(presented_session_hash)<>32 OR
       replay_key_id IS NULL OR replay_key_id !~ '^[0-9a-f]{16}$' OR
       replay_nonce IS NULL OR octet_length(replay_nonce)<>12 OR
       replay_ciphertext IS NULL OR
       octet_length(replay_ciphertext) NOT BETWEEN 16 AND 1057808 OR
       requested_ttl_seconds IS NULL OR requested_ttl_seconds NOT BETWEEN 60 AND 86400 THEN
        RETURN FALSE;
    END IF;
    PERFORM 1 FROM users AS actor
     WHERE actor.id=requested_actor AND actor.auth_generation=expected_generation
       AND actor.is_admin AND NOT actor.is_disabled FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    PERFORM 1 FROM api_sessions AS session
     WHERE session.user_id=requested_actor
       AND session.token_hash=presented_session_hash
       AND session.expires_at>clock_timestamp() FOR SHARE;
    IF NOT FOUND THEN RETURN FALSE; END IF;

    SELECT entry.* INTO reservation FROM api_idempotency_records AS entry
     WHERE entry.id=requested_record AND entry.lease_token=requested_lease
       AND entry.state='started' AND entry.lease_expires_at>clock_timestamp()
       AND entry.expires_at>clock_timestamp()
       AND entry.request_actor_id=requested_actor
       AND entry.principal_kind='admin' AND entry.method='POST'
       AND entry.route='/api/v1/admin/tls/reload' FOR UPDATE;
    IF NOT FOUND THEN RETURN FALSE; END IF;
    IF replay_key_id<>reservation.scope_key_id THEN RETURN FALSE; END IF;

    INSERT INTO api_operation_journal (
        id,request_id,idempotency_id,actor_id,actor_subject_id,
        actor_auth_generation,authorization_policy,kind,target,
        payload_version,payload,max_attempts,deadline_at
    ) VALUES (
        requested_operation,reservation.request_id,reservation.id,
        requested_actor,requested_actor,expected_generation,
        'reauthorize_until_effect','admin.tls_reload',NULL,
        1,'{}'::jsonb,8,clock_timestamp()+INTERVAL '24 hours'
    );
    INSERT INTO audit_log (
        actor_id,action,target,details,request_id,operation_id
    ) VALUES (
        requested_actor,'api.operation.transition',NULL,
        jsonb_build_object('phase','requested','kind','admin.tls_reload',
                           'status','pending','details','{}'::jsonb),
        reservation.request_id,requested_operation
    );
    UPDATE api_idempotency_records AS entry
       SET state='completed',lease_token=NULL,lease_expires_at=NULL,
           response_status=202,response_key_id=replay_key_id,
           response_nonce=replay_nonce,response_ciphertext=replay_ciphertext,
           expires_at=clock_timestamp()+requested_ttl_seconds*INTERVAL '1 second',
           completed_at=clock_timestamp(),updated_at=clock_timestamp()
     WHERE entry.id=requested_record AND entry.lease_token=requested_lease
       AND entry.state='started';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'TLS reload lease changed before response commit'
          USING ERRCODE='55000';
    END IF;
    RETURN TRUE;
END;
$northstar_admin_tls_reload_commit$;

DO $pin_admin_tls_reload_command$
DECLARE
    migration_schema pg_catalog.text := pg_catalog.current_schema();
    routine_signature pg_catalog.text;
BEGIN
    FOREACH routine_signature IN ARRAY ARRAY[
        'northstar_admin_tls_reload_admit(uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,bytea,text,uuid,int8,int8)',
        'northstar_admin_tls_reload_rekey(uuid,uuid,int8,bytea,bytea,bytea,bytea,bytea,bytea,text,bytea,bytea)',
        'northstar_admin_tls_reload_commit(uuid,uuid,uuid,int8,bytea,uuid,text,bytea,bytea,int8)'
    ] LOOP
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s RESET ALL',migration_schema,routine_signature
        );
        EXECUTE pg_catalog.format(
            'ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp',
            migration_schema,routine_signature,migration_schema
        );
        EXECUTE pg_catalog.format(
            'REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC',migration_schema,routine_signature
        );
    END LOOP;
END;
$pin_admin_tls_reload_command$;
