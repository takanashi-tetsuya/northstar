-- Source this inside the replacement transaction, after pg_restore and before
-- its COMMIT. Older dumps do not contain this table. Never trust a restored
-- table merely because its name matches.
CREATE TABLE IF NOT EXISTS northstar_restore_outcome_markers (
    restore_id pg_catalog.text NOT NULL CHECK (restore_id ~ '^[0-9a-f]{32}$'),
    manifest_sha256 pg_catalog.bytea NOT NULL CHECK (pg_catalog.octet_length(manifest_sha256)=32),
    target_database_oid pg_catalog.oid NOT NULL,
    outcome pg_catalog.text NOT NULL CHECK (outcome IN ('incoming','rollback')),
    transaction_xid pg_catalog.xid8 NOT NULL,
    recorded_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (restore_id,outcome)
);
REVOKE ALL ON northstar_restore_outcome_markers FROM PUBLIC;

CREATE TEMPORARY TABLE northstar_expected_restore_marker_shape (
    restore_id pg_catalog.text NOT NULL CHECK (restore_id ~ '^[0-9a-f]{32}$'),
    manifest_sha256 pg_catalog.bytea NOT NULL CHECK (pg_catalog.octet_length(manifest_sha256)=32),
    target_database_oid pg_catalog.oid NOT NULL,
    outcome pg_catalog.text NOT NULL CHECK (outcome IN ('incoming','rollback')),
    transaction_xid pg_catalog.xid8 NOT NULL,
    recorded_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (restore_id,outcome)
) ON COMMIT DROP;

DO $northstar_restore_marker_attestation$
DECLARE
    marker pg_catalog.oid;
    target_schema pg_catalog.text := pg_catalog.current_schema();
    actual_columns pg_catalog.text[];
BEGIN
    IF target_schema IS NULL OR target_schema IN ('pg_catalog','information_schema')
       OR target_schema LIKE 'pg_temp_%' THEN
        RAISE EXCEPTION 'restore marker requires the application schema first in search_path'
            USING ERRCODE='3F000';
    END IF;
    marker := pg_catalog.to_regclass(
        pg_catalog.format('%I.%I',target_schema,'northstar_restore_outcome_markers')
    );
    IF marker IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE c.oid=marker AND c.relkind='r' AND NOT c.relispartition
          AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
          AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER)
          AND n.nspname=target_schema AND n.nspowner=c.relowner
    ) THEN
        RAISE EXCEPTION 'restore marker relation ownership or shape is unsafe'
            USING ERRCODE='42501';
    END IF;
    SELECT pg_catalog.array_agg(
        a.attname || ':' || pg_catalog.format_type(a.atttypid,a.atttypmod)
        || ':' || a.attnotnull::pg_catalog.text ORDER BY a.attnum
    ) INTO actual_columns
    FROM pg_catalog.pg_attribute a
    WHERE a.attrelid=marker AND a.attnum>0 AND NOT a.attisdropped;
    IF actual_columns IS DISTINCT FROM ARRAY[
        'restore_id:text:true', 'manifest_sha256:bytea:true',
        'target_database_oid:oid:true', 'outcome:text:true',
        'transaction_xid:xid8:true', 'recorded_at:timestamp with time zone:true'
    ]::pg_catalog.text[] THEN
        RAISE EXCEPTION 'restore marker columns do not match the trusted schema'
            USING ERRCODE='42501';
    END IF;
    IF (SELECT pg_catalog.array_agg(
            contype::pg_catalog.text || ':' ||
            pg_catalog.pg_get_constraintdef(oid,TRUE)
            ORDER BY contype,pg_catalog.pg_get_constraintdef(oid,TRUE))
        FROM pg_catalog.pg_constraint WHERE conrelid=marker)
       IS DISTINCT FROM
       (SELECT pg_catalog.array_agg(
            contype::pg_catalog.text || ':' ||
            pg_catalog.pg_get_constraintdef(oid,TRUE)
            ORDER BY contype,pg_catalog.pg_get_constraintdef(oid,TRUE))
        FROM pg_catalog.pg_constraint
        WHERE conrelid='pg_temp.northstar_expected_restore_marker_shape'::pg_catalog.regclass)
       OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))
        ) acl
        WHERE c.oid=marker AND acl.grantee<>c.relowner
       )
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
                  WHERE tgrelid=marker AND NOT tgisinternal)
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid=marker)
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_inherits
                  WHERE inhrelid=marker OR inhparent=marker)
       OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index WHERE indrelid=marker)<>1
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite
                  WHERE ev_class=marker AND rulename<>'_RETURN') THEN
        RAISE EXCEPTION 'restore marker constraints, ACL, or hooks are unsafe'
            USING ERRCODE='42501';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
        WHERE a.attrelid=marker AND a.attname='recorded_at'
          AND pg_catalog.pg_get_expr(d.adbin,d.adrelid)='clock_timestamp()'
    ) THEN
        RAISE EXCEPTION 'restore marker timestamp default is unsafe'
            USING ERRCODE='42501';
    END IF;
END;
$northstar_restore_marker_attestation$ LANGUAGE plpgsql;
