#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

invalid=$(find migrations -maxdepth 1 -type f -name '*.sql' -print \
    | grep -Ev '^migrations/[0-9]{4}_[a-z0-9_]+\.sql$' || true)
if [ -n "$invalid" ]; then
    echo "database migrations must use NNNN_lowercase_name.sql:" >&2
    printf '%s\n' "$invalid" >&2
    exit 1
fi

duplicates=$(find migrations -maxdepth 1 -type f -name '*.sql' -print \
    | sed -n 's#^.*/\([0-9][0-9]*\)_.*\.sql$#\1#p' \
    | sort \
    | uniq -d)
if [ -n "$duplicates" ]; then
    echo "database migration version prefixes are duplicated:" >&2
    printf '%s\n' "$duplicates" >&2
    exit 1
fi

# Version 0021 was intentionally never assigned.  Keep that reservation
# explicit so a missing migration cannot be confused with the historical gap,
# and never add a late low-number migration that may run after newer releases.
reserved_versions="21"
versions=$(find migrations -maxdepth 1 -type f -name '*.sql' -print \
    | sed -n 's#^.*/\([0-9][0-9]*\)_.*\.sql$#\1#p' \
    | sed 's/^0*//; s/^$/0/' \
    | sort -n)
latest=$(printf '%s\n' "$versions" | tail -n 1)
[ -n "$latest" ] || {
    echo "database migrations are missing" >&2
    exit 1
}
if printf '%s\n' "$versions" | grep -qx 0; then
    echo "database migration version 0000 is invalid" >&2
    exit 1
fi

missing=""
version=1
while [ "$version" -le "$latest" ]; do
    case " $reserved_versions " in
        *" $version "*) ;;
        *)
            if ! printf '%s\n' "$versions" | grep -qx "$version"; then
                missing="$missing $version"
            fi
            ;;
    esac
    version=$((version + 1))
done
if [ -n "$missing" ]; then
    echo "database migration sequence has an unreserved gap:$missing" >&2
    exit 1
fi

for reserved in $reserved_versions; do
    if printf '%s\n' "$versions" | grep -qx "$reserved"; then
        echo "database migration version $(printf '%04d' "$reserved") is reserved and must remain unused" >&2
        exit 1
    fi
done

echo "database migration versions are unique and continuous (0021 is reserved)"

# PostgreSQL SQL aliases such as BIGINT and BOOLEAN are rewritten by the
# parser only when they are unqualified. Once a schema is specified PostgreSQL
# performs a catalog lookup, where the real type names are int8 and bool. Keep
# every migration from reintroducing an alias that will fail while a PL/pgSQL
# function body is parsed on a fresh database.
invalid_catalog_type_aliases=$(grep -Ein \
    'pg_catalog\.(bigint|boolean|integer|smallint|int|float|real|decimal|dec|serial|bigserial|smallserial|character([[:space:]]+varying)?|double[[:space:]]+precision|bit[[:space:]]+varying)([^[:alnum:]_]|$)' \
    migrations/*.sql || true)
if [ -n "$invalid_catalog_type_aliases" ]; then
    echo "database migrations use schema-qualified PostgreSQL type aliases; use catalog typnames such as int8, bool, int4, int2, float4, float8, numeric, varchar or varbit:" >&2
    printf '%s\n' "$invalid_catalog_type_aliases" >&2
    exit 1
fi
echo "schema-qualified PostgreSQL migration types use real catalog names"

# SQL context values such as CURRENT_USER are parser keywords, not catalog
# functions or columns. Qualifying them makes PostgreSQL parse `pg_catalog` as
# a table alias and fails a fresh migration with a missing-FROM error.
invalid_catalog_context_keywords=$(grep -Ein \
    'pg_catalog\.(current_user|session_user|current_role|current_catalog)([^[:alnum:]_]|$)' \
    migrations/*.sql || true)
if [ -n "$invalid_catalog_context_keywords" ]; then
    echo "database migrations must not schema-qualify SQL context keywords such as CURRENT_USER:" >&2
    printf '%s\n' "$invalid_catalog_context_keywords" >&2
    exit 1
fi
echo "SQL context keywords are not misqualified as pg_catalog relations"

# PL/pgSQL reads IF conditions up to a zero-parenthesis-depth THEN token. An
# unparenthesized CASE operand can therefore make its inner THEN terminate the
# surrounding IF expression. Requiring parentheses is harmless in plain SQL
# and prevents this parser ambiguity in procedural bodies.
unparenthesized_case_operands=$(grep -Ein \
    '(^|[[:space:]])(AND|OR)[[:space:]]+CASE([[:space:]]|$)' \
    migrations/*.sql || true)
if [ -n "$unparenthesized_case_operands" ]; then
    echo "database migrations must parenthesize CASE operands after AND/OR:" >&2
    printf '%s\n' "$unparenthesized_case_operands" >&2
    exit 1
fi
echo "CASE operands cannot terminate PL/pgSQL IF parsing at an inner THEN"

# Every migration must honor the connection's selected application schema.
# An explicit public qualifier bypasses isolated test/deployment schemas and
# can read or mutate an unrelated tenant's historical objects.
hardcoded_public_migration_refs=$(grep -Ein \
    '(^|[^[:alnum:]_])public[[:space:]]*\.' migrations/*.sql || true)
if [ -n "$hardcoded_public_migration_refs" ]; then
    echo "database migrations must not hard-code the public schema:" >&2
    printf '%s\n' "$hardcoded_public_migration_refs" >&2
    exit 1
fi
canonical_security_definer_count=$(grep -Eic \
    'LANGUAGE[[:space:]]+plpgsql[[:space:]]+SECURITY[[:space:]]+DEFINER' \
    migrations/*.sql | awk -F: '{ total += $NF } END { print total + 0 }')
if [ "$canonical_security_definer_count" -ne 50 ]; then
    echo "migration sources must contain exactly 50 canonical single-line PL/pgSQL SECURITY DEFINER declarations (0111 adds eight PL/pgSQL XEP-0133 cleanup issuers/claimants; 0124 adds the fenced authentication credential upgrade; 0125 replaces registration with a fail-closed control lookup; 0107's multiline declaration and 0111's read-only SQL snapshot are checked separately)" >&2
    exit 1
fi
echo "database migrations contain no hard-coded public schema references; SECURITY DEFINER set is exact"

database_capability_migration="migrations/0107_database_capability_hardening.sql"
[ -f "$database_capability_migration" ] || {
    echo "database capability hardening migration is missing: $database_capability_migration" >&2
    exit 1
}
for required_fragment in \
    "current_user <> pg_catalog.pg_get_userbyid(" \
    "relation.oid=TG_RELID" \
    "untrusted audit cleanup marker" \
    "untrusted legal-hold snapshot cleanup marker" \
    "untrusted governance-export cleanup marker" \
    "untrusted cluster MUC cleanup marker" \
    "CREATE OR REPLACE FUNCTION northstar_release_legal_hold(" \
    "SECURITY DEFINER" \
    "ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp" \
    "REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC" \
    "migration_schema pg_catalog.text := pg_catalog.current_schema()"
do
    grep -Fq "$required_fragment" "$database_capability_migration" || {
        echo "migration 0107 is missing database capability invariant: $required_fragment" >&2
        exit 1
    }
done
if [ "$(grep -Fc 'relation.oid=TG_RELID' "$database_capability_migration")" -ne 4 ]; then
    echo "migration 0107 must bind all four marker guards to their exact relation owner" >&2
    exit 1
fi
for capability in \
    northstar_purge_released_hold_offline_snapshots \
    northstar_purge_audit_log \
    northstar_purge_governance_export_leases \
    northstar_purge_cluster_muc_history \
    northstar_release_legal_hold
do
    grep -Fq "'$capability(" "$database_capability_migration" || {
        echo "migration 0107 capability manifest omits $capability" >&2
        exit 1
    }
done
echo "migration 0107 binds cleanup provenance to owner-held, schema-pinned capabilities"

user_capability_migration="migrations/0108_user_command_capabilities.sql"
[ -f "$user_capability_migration" ] || {
    echo "user command capability migration is missing: $user_capability_migration" >&2
    exit 1
}
if [ "$(grep -Eic 'LANGUAGE[[:space:]]+plpgsql[[:space:]]+SECURITY[[:space:]]+DEFINER' "$user_capability_migration")" -ne 35 ]; then
    echo "migration 0108 must define exactly 35 typed PL/pgSQL SECURITY DEFINER commands" >&2
    exit 1
fi
for required_fragment in \
    "migration_schema pg_catalog.text := pg_catalog.current_schema()" \
    "ALTER FUNCTION %I.%s SECURITY DEFINER SET search_path TO pg_catalog, %I, pg_temp" \
    "REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC" \
    "SELECT COALESCE(" \
    "requested_actor_id=requested_target_id" \
    "auth_generation=expected_actor_generation" \
    "CREATE TABLE admin_command_capability_authority" \
    "ADD COLUMN bearer_hash BYTEA NOT NULL" \
    "ADD COLUMN claim_hash BYTEA" \
    "northstar_admin_command_claim_hash(" \
    "northstar_admin_command_complete_locked(" \
    "northstar_admin_service_control_poll("
do
    grep -Fq "$required_fragment" "$user_capability_migration" || {
        echo "migration 0108 is missing user-command invariant: $required_fragment" >&2
        exit 1
    }
done
echo "migration 0108 binds 35 fail-closed account/XEP-0133 commands to its owner and installation schema"

admin_cleanup_migration="migrations/0111_admin_session_cleanup_effects.sql"
[ -f "$admin_cleanup_migration" ] || {
    echo "administrator session cleanup migration is missing: $admin_cleanup_migration" >&2
    exit 1
}
if [ "$(grep -Eic 'LANGUAGE[[:space:]]+(sql[[:space:]]+STABLE[[:space:]]+|plpgsql[[:space:]]+)SECURITY[[:space:]]+DEFINER' "$admin_cleanup_migration")" -ne 9 ]; then
    echo "migration 0111 must define exactly nine owner-held cleanup issuer/claimant capabilities" >&2
    exit 1
fi
for required_fragment in \
    "CREATE TABLE admin_session_cleanup_effects" \
    "CHECK(queued BETWEEN 0 AND 100000)" \
    "CONSTRAINT admin_session_cleanup_effect_identity UNIQUE(command_operation_id,effect_key)" \
    "deployment_session_leases lease" \
    "FOR UPDATE SKIP LOCKED" \
    "lease_expires_at>pg_catalog.clock_timestamp()" \
    "northstar_enqueue_admin_generation_cleanup(" \
    "northstar_enqueue_admin_exact_session_cleanup(" \
    "northstar_admin_command_issue_delete_cleanup(" \
    "DROP FUNCTION northstar_admin_command_reset_user_password(" \
    "DROP FUNCTION northstar_admin_command_user_lifecycle(" \
    "ALTER FUNCTION %I.%s SET search_path TO pg_catalog, %I, pg_temp" \
    "REVOKE ALL ON FUNCTION %I.%s FROM PUBLIC"
do
    grep -Fq "$required_fragment" "$admin_cleanup_migration" || {
        echo "migration 0111 is missing administrator cleanup invariant: $required_fragment" >&2
        exit 1
    }
done
if grep -Eiq 'REFERENCES[[:space:]]+users' "$admin_cleanup_migration"; then
    echo "migration 0111 cleanup effects must survive account deletion and cannot reference users" >&2
    exit 1
fi
echo "migration 0111 transactionally issues bounded, replay-safe administrator session cleanup effects"

# Migration 0091 is deliberately portable to a caller-selected application
# schema. A SECURITY DEFINER function must never fall back to a stale public
# table in a shared development database, and the checked offline function
# must be created only after all of its referenced queues exist.
shared_upload_migration="migrations/0091_shared_upload_storage.sql"
[ -f "$shared_upload_migration" ] || {
    echo "shared upload migration is missing: $shared_upload_migration" >&2
    exit 1
}
hardcoded_shared_upload_schema=$(grep -Ein '(^|[^[:alnum:]_])public\.' "$shared_upload_migration" || true)
if [ -n "$hardcoded_shared_upload_schema" ]; then
    echo "migration 0091 must resolve application objects only through its captured migration schema:" >&2
    printf '%s\n' "$hardcoded_shared_upload_schema" >&2
    exit 1
fi
fail_closed_definer_paths=$(grep -Ec \
    'SECURITY DEFINER SET search_path=pg_catalog,pg_temp' "$shared_upload_migration")
if [ "$fail_closed_definer_paths" -ne 3 ]; then
    echo "migration 0091 must create all three SECURITY DEFINER functions with a fail-closed temporary search_path" >&2
    exit 1
fi
if grep -Fq 'SET search_path FROM CURRENT' "$shared_upload_migration"; then
    echo "migration 0091 must not persist a transaction-local or caller-controlled search_path" >&2
    exit 1
fi
if [ "$(grep -Ec "SET search_path TO pg_catalog, %I, pg_temp'" "$shared_upload_migration")" -ne 3 ]; then
    echo "migration 0091 must bind all three definer functions to a quoted, catalog-first installation schema" >&2
    exit 1
fi
for secured_function in \
    offline_upgrade_upload_storage_authority_v1_to_v2 \
    account_upload_storage_job_capacity \
    account_upload_cleanup_capacity
do
    if ! grep -Eq "ALTER FUNCTION %I\.${secured_function}\(" "$shared_upload_migration"; then
        echo "migration 0091 does not safely bind ${secured_function} to its installation schema" >&2
        exit 1
    fi
done
for unsafe_schema_guard in \
    "'pg_catalog','information_schema'" \
    "LIKE 'pg_temp_%'" \
    "LIKE 'pg_toast_temp_%'"
do
    if ! grep -Fq "$unsafe_schema_guard" "$shared_upload_migration"; then
        echo "migration 0091 does not reject unsafe schema class: $unsafe_schema_guard" >&2
        exit 1
    fi
done
for prerequisite in upload_slots upload_cleanup_queue upload_cleanup_queue_order_idx; do
    if ! grep -Fq "pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,'${prerequisite}'))" "$shared_upload_migration"; then
        echo "migration 0091 does not require ${prerequisite} in its selected installation schema" >&2
        exit 1
    fi
done
jobs_line=$(grep -n -m1 '^CREATE TABLE upload_storage_jobs (' "$shared_upload_migration" | cut -d: -f1)
cleanup_line=$(grep -n -m1 '^ALTER TABLE upload_cleanup_queue ADD CONSTRAINT upload_cleanup_queue_state_check' "$shared_upload_migration" | cut -d: -f1)
offline_function_line=$(grep -n -m1 '^CREATE FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(' "$shared_upload_migration" | cut -d: -f1)
if [ -z "$jobs_line" ] || [ -z "$cleanup_line" ] || [ -z "$offline_function_line" ] \
   || [ "$offline_function_line" -le "$jobs_line" ] \
   || [ "$offline_function_line" -le "$cleanup_line" ]; then
    echo "migration 0091 creates its checked offline authority function before all referenced relations" >&2
    exit 1
fi
fixed_path_line=$(grep -n -m1 '^\$northstar_upload_function_paths\$;$' "$shared_upload_migration" | cut -d: -f1)
[ -n "$fixed_path_line" ] || {
    echo "migration 0091 fixed SECURITY DEFINER path block is incomplete" >&2
    exit 1
}
for capacity_trigger in \
    upload_job_capacity_insert \
    upload_job_capacity_delete \
    upload_cleanup_capacity_insert \
    upload_cleanup_capacity_delete
do
    trigger_line=$(grep -n -m1 "^CREATE TRIGGER ${capacity_trigger}" "$shared_upload_migration" | cut -d: -f1)
    if [ -z "$trigger_line" ] || [ "$trigger_line" -le "$fixed_path_line" ]; then
        echo "migration 0091 attaches ${capacity_trigger} before fixing its definer function schema" >&2
        exit 1
    fi
done
echo "migration 0091 SECURITY DEFINER functions are isolated-schema safe"

# Migration 0105 repairs account-cascade cleanup without treating trigger
# nesting alone as authority.  Only the reviewed upload_slots delete trigger
# may assert the immutable provenance bit; direct queue writers retain 0091's
# exact slot update and capacity behavior.
upload_cascade_capacity_migration="migrations/0105_upload_cascade_cleanup_capacity.sql"
[ -f "$upload_cascade_capacity_migration" ] || {
    echo "upload cascade capacity migration is missing: $upload_cascade_capacity_migration" >&2
    exit 1
}
for required_fragment in \
    'ADD COLUMN slot_delete_projection pg_catalog.bool NOT NULL DEFAULT FALSE' \
    'ADD COLUMN recovery_retained_files pg_catalog.int8 NOT NULL DEFAULT 0' \
    'ADD COLUMN recovery_retained_bytes pg_catalog.int8 NOT NULL DEFAULT 0' \
    'ADD COLUMN configured_retained_files_limit pg_catalog.int8' \
    'ADD COLUMN configured_retained_bytes_limit pg_catalog.int8' \
    'ALTER TABLE upload_storage_jobs ALTER COLUMN expected_size SET NOT NULL' \
    "trigger_row.tgname='upload_storage_delete_queue'" \
    "function_row.proname='queue_upload_storage_delete'" \
    'matching_triggers<>1' \
    "trigger_row.tgenabled IN ('O','A')" \
    'trigger_row.tgqual IS NULL' \
    "'upload_slot_cleanup_debt_reserve'" \
    "'upload_slot_capacity_insert'" \
    "'upload_slot_capacity_delete'" \
    "'upload_job_capacity_insert'" \
    "'upload_job_capacity_delete'" \
    "'upload_cleanup_capacity_insert'" \
    "'upload_cleanup_capacity_delete'" \
    "'upload_storage_job_identity_guard'" \
    "'upload_cleanup_identity_guard'" \
    "'upload_capacity_policy_guard'" \
    "'protect_upload_storage_job_identity'" \
    "'protect_upload_cleanup_identity'" \
    "'protect_upload_capacity_policy'" \
    'must have one exact attachment in the installation schema' \
    'must have exactly one INSERT and one DELETE attachment' \
    'ON CONFLICT(object_id) DO NOTHING' \
    'IF OLD.storage_cleanup_debt_reserved THEN' \
    'NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection' \
    'IF pg_catalog.pg_trigger_depth()<=1 THEN' \
    'IF NOT converts_debt THEN' \
    'IF converts_debt AND NOT NEW.slot_delete_projection THEN' \
    'CREATE OR REPLACE FUNCTION account_upload_slot_capacity()' \
    'last upload storage projection has unknown retained size' \
    'recovery_retained_files=recovery_retained_files+1' \
    'recovery_retained_files=recovery_retained_files+locator_units' \
    'recovery_retained_files=recovery_retained_files-1' \
    'recovery_retained_files=recovery_retained_files-locator_units' \
    'hand ownership back to' \
    'requested_retained_files_limit pg_catalog.int8' \
    'requested_retained_bytes_limit pg_catalog.int8' \
    'COALESCE(OLD.storage_object_version,OLD.storage_stage_version)' \
    'NOT EXISTS(SELECT 1 FROM upload_cleanup_queue' \
    'NOT EXISTS(SELECT 1 FROM upload_storage_jobs' \
    'SET search_path TO pg_catalog, %I, pg_temp'
do
    if ! grep -Fq "$required_fragment" "$upload_cascade_capacity_migration"; then
        echo "migration 0105 lacks explicit cascade provenance invariant: $required_fragment" >&2
        exit 1
    fi
done
if [ "$(grep -Fc 'ADD COLUMN slot_delete_projection' "$upload_cascade_capacity_migration")" -ne 1 ] \
   || [ "$(grep -Fc 'NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection' "$upload_cascade_capacity_migration")" -ne 1 ] \
   || [ "$(grep -Fc 'IF pg_catalog.pg_trigger_depth()<=1 THEN' "$upload_cascade_capacity_migration")" -ne 1 ] \
   || [ "$(grep -Ec '^[[:space:]]*TRUE[[:space:]]*$' "$upload_cascade_capacity_migration")" -ne 1 ]; then
    echo "migration 0105 provenance must exist only on the unified cleanup tombstone" >&2
    exit 1
fi
delete_trigger_body=$(sed -n \
    '/^CREATE OR REPLACE FUNCTION queue_upload_storage_delete()/,/^\$\$ LANGUAGE plpgsql;$/p' \
    "$upload_cascade_capacity_migration")
if [ "$(printf '%s\n' "$delete_trigger_body" | grep -Fc 'GET DIAGNOSTICS inserted_count=ROW_COUNT')" -ne 1 ] \
   || printf '%s\n' "$delete_trigger_body" | grep -Fq 'DO UPDATE SET' \
   || printf '%s\n' "$delete_trigger_body" | grep -Fq 'INSERT INTO upload_storage_jobs'; then
    echo "migration 0105 cascade conflicts must fail closed after exact DO NOTHING inspection" >&2
    exit 1
fi
echo "migration 0105 upload cascade provenance and capacity conversion are explicit"

# Migration 0094 installs SECURITY DEFINER functions into the connection's
# active migration schema. They must never escape an isolated schema by naming
# shared `public` relations, nor inherit the caller's search_path. The migration
# captures its installation schema as a quoted identifier and fixes both
# functions to a catalog-first, application-schema, pg_temp-last path.
cluster_muc_delivery_migration="migrations/0094_cluster_muc_delivery_receipts.sql"
[ -f "$cluster_muc_delivery_migration" ] || {
    echo "cluster MUC delivery migration is missing: $cluster_muc_delivery_migration" >&2
    exit 1
}
if grep -Ein '(^|[^[:alnum:]_])public\.' "$cluster_muc_delivery_migration" >/dev/null; then
    echo "migration 0094 SECURITY DEFINER code must not address shared public relations" >&2
    grep -Ein '(^|[^[:alnum:]_])public\.' "$cluster_muc_delivery_migration" >&2
    exit 1
fi
if [ "$(grep -Ec 'SECURITY DEFINER SET search_path=pg_catalog,pg_temp' "$cluster_muc_delivery_migration")" -ne 2 ]; then
    echo "migration 0094 must create both SECURITY DEFINER functions with a fail-closed temporary search_path" >&2
    exit 1
fi
if [ "$(grep -Ec "SET search_path TO pg_catalog, %I, pg_temp'" "$cluster_muc_delivery_migration")" -ne 2 ]; then
    echo "migration 0094 must bind both SECURITY DEFINER functions to a quoted, catalog-first installation schema" >&2
    exit 1
fi
for secured_function in \
    northstar_transfer_cluster_muc_outbox \
    fence_cluster_muc_outbox_identity
do
    if ! grep -Eq "ALTER FUNCTION %I\.${secured_function}\(" "$cluster_muc_delivery_migration"; then
        echo "migration 0094 does not safely bind ${secured_function} to its installation schema" >&2
        exit 1
    fi
done
if ! grep -Fq 'migration_schema pg_catalog.text := pg_catalog.current_schema()' "$cluster_muc_delivery_migration"; then
    echo "migration 0094 must capture its active installation schema through pg_catalog" >&2
    exit 1
fi
if ! grep -Fq "USING ERRCODE = '3F000'" "$cluster_muc_delivery_migration"; then
    echo "migration 0094 must fail closed when its installation schema is unsafe" >&2
    exit 1
fi
for prerequisite in cluster_muc_event_outbox cluster_muc_occupancies; do
    if ! grep -Fq "migration_schema, '$prerequisite'" "$cluster_muc_delivery_migration"; then
        echo "migration 0094 does not bind prerequisite $prerequisite to its exact installation schema" >&2
        exit 1
    fi
done
prerequisite_guard_line=$(grep -n -m1 '^DO \$cluster_muc_delivery_prerequisites\$' "$cluster_muc_delivery_migration" | cut -d: -f1)
first_delivery_table_line=$(grep -n -m1 '^CREATE TABLE cluster_muc_event_delivery_items (' "$cluster_muc_delivery_migration" | cut -d: -f1)
if [ -z "$prerequisite_guard_line" ] || [ -z "$first_delivery_table_line" ] \
   || [ "$prerequisite_guard_line" -ge "$first_delivery_table_line" ]; then
    echo "migration 0094 must validate schema-local prerequisites before creating foreign keys" >&2
    exit 1
fi
if ! grep -Fq "USING ERRCODE = '42P01'" "$cluster_muc_delivery_migration"; then
    echo "migration 0094 must fail closed when schema-local prerequisites are absent" >&2
    exit 1
fi
echo "migration 0094 SECURITY DEFINER functions are isolated to their quoted installation schema"

# Migration 0098 repairs migration 0087's BEFORE UPDATE return value and pins
# every lifecycle routine to its installation schema without introducing an
# elevated routine or changing ACLs.
data_lifecycle_safety_migration="migrations/0098_data_lifecycle_trigger_safety.sql"
[ -f "$data_lifecycle_safety_migration" ] || {
    echo "data lifecycle trigger safety migration is missing: $data_lifecycle_safety_migration" >&2
    exit 1
}
for required_fragment in \
    "CREATE OR REPLACE FUNCTION protect_held_data_record()" \
    "IF TG_OP='DELETE' THEN" \
    'RETURN OLD;' \
    'RETURN NEW;' \
    'migration_schema pg_catalog.text := pg_catalog.current_schema()' \
    "ALTER FUNCTION %I.%s SET search_path TO pg_catalog, %I, pg_temp"
do
    if ! grep -Fq "$required_fragment" "$data_lifecycle_safety_migration"; then
        echo "migration 0098 is missing required lifecycle guard: $required_fragment" >&2
        exit 1
    fi
done
for lifecycle_routine in \
    release_offline_message_admission_capacity \
    detach_delivered_offline_message_admission \
    preserve_held_offline_message \
    protect_held_data_record \
    protect_legal_hold_subject_delete \
    enforce_legal_hold_history \
    prevent_legal_hold_link_mutation \
    enforce_audit_log_immutability \
    northstar_purge_released_hold_offline_snapshots \
    northstar_purge_audit_log
do
    if ! grep -Fq "'$lifecycle_routine(" "$data_lifecycle_safety_migration"; then
        echo "migration 0098 does not bind lifecycle routine: $lifecycle_routine" >&2
        exit 1
    fi
done
if grep -Eiq 'SECURITY[[:space:]]+DEFINER|(^|[[:space:]])(GRANT|REVOKE)([[:space:]]|$)|ALTER[[:space:]]+(FUNCTION|ROUTINE)[^;]*OWNER' \
    "$data_lifecycle_safety_migration"; then
    echo "migration 0098 must not elevate lifecycle routines or change their ACL/owner" >&2
    exit 1
fi
echo "migration 0098 preserves UPDATE rows and pins lifecycle invokers without ACL expansion"

application_function_path_migration="migrations/0099_application_function_search_path.sql"
[ -f "$application_function_path_migration" ] || {
    echo "application function path migration is missing: $application_function_path_migration" >&2
    exit 1
}
for required_fragment in \
    'migration_schema pg_catalog.text := pg_catalog.current_schema()' \
    'FROM pg_catalog.pg_proc proc_row' \
    "proc_language.lanname IN ('plpgsql','sql')" \
    "dependency.deptype='e'" \
    'pg_catalog.pg_get_function_identity_arguments(proc_row.oid)' \
    'routine.proowner<>migration_owner' \
    'ALTER FUNCTION %I.%I(%s) SET search_path TO pg_catalog, %I, pg_temp' \
    'proc_row.proowner=routine.proowner' \
    'proc_row.prosecdef=routine.prosecdef' \
    'proc_row.proacl IS NOT DISTINCT FROM routine.proacl'
do
    if ! grep -Fq "$required_fragment" "$application_function_path_migration"; then
        echo "migration 0099 is missing application-function invariant: $required_fragment" >&2
        exit 1
    fi
done
if grep -Eiq '(^|[[:space:]])(GRANT|REVOKE)([[:space:]]|$)|ALTER[[:space:]]+(FUNCTION|ROUTINE)[^;]*OWNER' \
    "$application_function_path_migration"; then
    echo "migration 0099 must not change application function ACLs or owners" >&2
    exit 1
fi
echo "migration 0099 pins every owned non-extension application function without authority changes"

# Migration 0113 is the sole runtime boundary for the five upload authority
# and recovery tables.  Keep this check independent of the global role
# manifest so adding unrelated capabilities cannot silently widen upload ACLs.
upload_authority_migration="migrations/0113_upload_authority_capabilities.sql"
[ -f "$upload_authority_migration" ] || {
    echo "upload authority capability migration is missing: $upload_authority_migration" >&2
    exit 1
}
if grep -Ein '(^|[^[:alnum:]_])public\.' "$upload_authority_migration" >/dev/null; then
    echo "migration 0113 must remain isolated-schema safe" >&2
    exit 1
fi
if grep -Eiq 'pg_catalog\.(bigint|boolean|integer|smallint|coalesce|greatest|least|extract|session_user)' \
    "$upload_authority_migration"; then
    echo "migration 0113 contains an invalid schema-qualified PostgreSQL alias/special form" >&2
    exit 1
fi
if [ "$(grep -Ec '^CREATE FUNCTION northstar_upload_[a-z0-9_]+\(' "$upload_authority_migration")" -ne 42 ]; then
    echo "migration 0113 must expose exactly 42 reviewed typed upload capabilities" >&2
    exit 1
fi
for required_fragment in \
    'existing upload locators have no namespace authority; use the offline namespace bootstrap procedure' \
    'ALL_NORTHSTAR_NODES_STOPPED_AND_EXISTING_UPLOAD_NAMESPACE_VERIFIED' \
    'configured_pending_limit IS NOT NULL' \
    'configured_retained_files_limit IS NOT NULL' \
    'configured_retained_bytes_limit IS NOT NULL' \
    'northstar_upload_begin_promotion(uuid,uuid,int8,uuid)' \
    'northstar_upload_complete_promotion(uuid,uuid,uuid,text,text,text,bytea,int8,int8,int8)' \
    'claim_expires_at=pg_catalog.clock_timestamp()+INTERVAL '\''240 seconds'\''' \
    'claim_token=requested_promotion_claim_token' \
    'runtime_routine_acl_mismatch AS (' \
    "routine.proname<>'northstar_upload_offline_bootstrap_authority'" \
    'FOR UPDATE SKIP LOCKED LIMIT 32' \
    'REVOKE ALL ON TABLE upload_storage_authority,'
do
    if ! grep -Fq "$required_fragment" "$upload_authority_migration"; then
        echo "migration 0113 is missing upload authority invariant: $required_fragment" >&2
        exit 1
    fi
done
# A marked multi-table JOIN lets PostgreSQL choose a row-lock order; bearer
# capabilities deliberately lock users and api_sessions in separate statements.
if grep -Fq 'FOR SHARE OF actor,session' "$upload_authority_migration"; then
    echo "migration 0113 must lock administrator bearer rows in users -> api_sessions order" >&2
    exit 1
fi
if grep -Eq 'after_(storage_job_id|cleanup_recovery_id) IS NULL[[:space:]]+OR' \
    "$upload_authority_migration"; then
    echo "migration 0113 dead-letter keysets must branch instead of using nullable-OR scans" >&2
    exit 1
fi
if grep -Fq 'northstar_upload_offline_bootstrap_authority' \
    deploy/postgres-init/lib/apply-northstar-grants.sql; then
    echo "offline upload namespace bootstrap must never be granted to runtime/command roles" >&2
    exit 1
fi
echo "migration 0113 upload authority capabilities are typed, fenced, bounded, and isolated-schema safe"

session_authority_migration="migrations/0114_session_authority_capabilities.sql"
[ -f "$session_authority_migration" ] || {
    echo "session authority capability migration is missing: $session_authority_migration" >&2
    exit 1
}
if grep -Ein '(^|[^[:alnum:]_])public\.' "$session_authority_migration" >/dev/null; then
    echo "migration 0114 must remain isolated-schema safe" >&2
    exit 1
fi
if [ "$(grep -Ec '^CREATE FUNCTION northstar_(session|sm)_[a-z0-9_]+\(' "$session_authority_migration")" -ne 29 ]; then
    echo "migration 0114 must expose exactly 29 reviewed session capabilities" >&2
    exit 1
fi
for required_fragment in \
    'northstar_session_capacity_reconcile_lock()' \
    'northstar_session_reserve_live(uuid,uuid,text,int8,bool)' \
    'northstar_session_transfer_sm(uuid,uuid,uuid,uuid,uuid,text,int8)' \
    'northstar_sm_claim(bytea,uuid,inet,uuid,text,bool,uuid,int8)' \
    'northstar_sm_take_teardown(text,uuid,uuid,int8,text,uuid,int8)' \
    'northstar_session_capability_catalog_healthy(text)' \
    'requested_claim_token' \
    'stream.auth_generation=account.auth_generation' \
    'stream.user_agent_id IS NULL' \
    'requested_device IS NULL' \
    'FOR UPDATE SKIP LOCKED' \
    'REVOKE ALL ON TABLE deployment_session_leases,'
do
    if ! grep -Fq "$required_fragment" "$session_authority_migration"; then
        echo "migration 0114 is missing session authority invariant: $required_fragment" >&2
        exit 1
    fi
done
echo "migration 0114 session authorities are capability-only, secret-private, bounded, and isolated-schema safe"

upload_runtime_bounds_migration="migrations/0115_upload_runtime_reconciliation_bounds.sql"
[ -f "$upload_runtime_bounds_migration" ] || {
    echo "upload runtime reconciliation bounds migration is missing: $upload_runtime_bounds_migration" >&2
    exit 1
}
if grep -Ein '(^|[^[:alnum:]_])public\.' "$upload_runtime_bounds_migration" >/dev/null; then
    echo "migration 0115 must remain isolated-schema safe" >&2
    exit 1
fi
for required_fragment in \
    'CREATE INDEX IF NOT EXISTS upload_storage_jobs_dead_idx' \
    'CREATE INDEX IF NOT EXISTS upload_cleanup_queue_recovery_dead_idx' \
    'CREATE INDEX IF NOT EXISTS upload_slots_storage_scrub_failures_idx' \
    "storage_backend='s3' AND storage_state='committed'" \
    'CREATE OR REPLACE FUNCTION northstar_upload_queue_snapshot()' \
    'bounded_dead_letters' \
    'bounded_scrub_failures' \
    'ALTER FUNCTION %I.northstar_upload_queue_snapshot() SECURITY DEFINER' \
    'SET search_path TO pg_catalog, %I, pg_temp' \
    'REVOKE ALL ON FUNCTION %I.northstar_upload_queue_snapshot() FROM PUBLIC' \
    'routine.proowner=migration_owner' \
    '1001 means at least 1001'
do
    if ! grep -Fq "$required_fragment" "$upload_runtime_bounds_migration"; then
        echo "migration 0115 is missing upload runtime-bound invariant: $required_fragment" >&2
        exit 1
    fi
done
if [ "$(grep -Fc 'LIMIT 1001' "$upload_runtime_bounds_migration")" -ne 4 ]; then
    echo "migration 0115 must cap exactly the dead-letter, scrub-failure, scrub-due, and cleanup-due probes at 1001" >&2
    exit 1
fi
if [ "$(grep -Ec '^CREATE OR REPLACE FUNCTION northstar_upload_queue_snapshot\(\)' "$upload_runtime_bounds_migration")" -ne 1 ]; then
    echo "migration 0115 must replace exactly one existing upload snapshot capability without changing its signature" >&2
    exit 1
fi
echo "migration 0115 bounds high-frequency upload health probes and preserves exact low-frequency reconciliation"

# Migration 0126 removes capacity-ledger contention from the post-socket MIX
# ACK path. Keep the release journal and stopped-writer cut-over explicit: an
# old trigger body or a direct capacity mutation here would recreate either
# silent overcommit or the original 55P03 delivery stall.
mix_delivery_release_migration="migrations/0126_mix_delivery_release_journal.sql"
[ -f "$mix_delivery_release_migration" ] || {
    echo "MIX delivery release-journal migration is missing: $mix_delivery_release_migration" >&2
    exit 1
}
for required_fragment in \
    'CREATE TABLE mix_delivery_capacity_releases (' \
    'release_id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid()' \
    'parent_event_id UUID' \
    'CREATE INDEX mix_delivery_capacity_releases_parent_idx' \
    'migration 0126 is intentionally a stopped-writer upgrade' \
    'MIX delivery capacity cut-over audit failed' \
    'ledger_rows NOT BETWEEN 0 AND 100000' \
    'ledger_bytes NOT BETWEEN 0 AND 268435456' \
    'CREATE OR REPLACE FUNCTION northstar_mix_delivery_recipient_capacity_delete()' \
    'CREATE OR REPLACE FUNCTION northstar_mix_delivery_event_capacity_delete()' \
    'CREATE FUNCTION northstar_mix_delivery_capacity_drain()' \
    'SECURITY DEFINER SET search_path TO pg_catalog' \
    'REVOKE ALL ON TABLE mix_delivery_capacity_releases FROM PUBLIC' \
    'INSERT INTO mix_delivery_capacity_releases(' \
    'DELETE FROM mix_delivery_events event'
do
    if ! grep -Fq "$required_fragment" "$mix_delivery_release_migration"; then
        echo "migration 0126 is missing MIX release-journal invariant: $required_fragment" >&2
        exit 1
    fi
done
if ! grep -Fq 'UNIQUE (event_id, recipient_jid)' migrations/0120_mix_delivery_normalization.sql; then
    echo "MIX release drain requires the existing event-leading recipient access path" >&2
    exit 1
fi
if [ "$(grep -Fc 'INSERT INTO mix_delivery_capacity_releases(' "$mix_delivery_release_migration")" -ne 2 ]; then
    echo "migration 0126 must journal exactly the recipient and event physical-delete credits" >&2
    exit 1
fi
if grep -Fq 'pg_try_advisory_xact_lock' "$mix_delivery_release_migration"; then
    echo "migration 0126 delete triggers must not acquire the producer capacity fence" >&2
    exit 1
fi
mix_ack_source=$(sed -n '/^async fn remove_mix_delivery_tx(/,/^async fn move_mix_delivery_to_dead_letter_tx(/p' src/db/mix.rs)
for forbidden_fragment in \
    'mix_delivery_events' \
    'mix_delivery_capacity' \
    'mix_delivery_recipient_sequences' \
    'pg_try_advisory_xact_lock'
do
    if printf '%s\n' "$mix_ack_source" | grep -Fq "$forbidden_fragment"; then
        echo "MIX completion must not touch shared event/sequence/capacity authority: $forbidden_fragment" >&2
        exit 1
    fi
done
for required_source_fragment in \
    "'mix-delivery-capacity-v3:'" \
    "('mix_delivery_capacity'::regclass)::oid::text" \
    'SELECT pg_advisory_xact_lock(' \
    'begin_mix_delivery_admission(pool).await?' \
    'FOR UPDATE OF event SKIP LOCKED' \
    'FROM mix_delivery_events WHERE event_id=$1 FOR UPDATE' \
    'ON CONFLICT(event_id) DO NOTHING' \
    'RETURNING event_id' \
    'SELECT jid,2 FROM input ORDER BY jid'
do
    if ! grep -Fq "$required_source_fragment" src/db/mix.rs; then
        echo "MIX capacity implementation is missing concurrency invariant: $required_source_fragment" >&2
        exit 1
    fi
done
mix_capacity_fence_source=$(sed -n '/^async fn acquire_mix_delivery_admission_fence_tx(/,/^fn mix_delivery_capacity_bucket(/p' src/db/mix.rs)
if printf '%s\n' "$mix_capacity_fence_source" | grep -Fq 'pg_try_advisory_xact_lock'; then
    echo "MIX producer authority must block at transaction start, not reject ordinary contention" >&2
    exit 1
fi
if [ "$(grep -Fc 'let _admission = self.delivery_admission_guard().await;' src/services/mix.rs)" -ne 18 ]; then
    echo "every MIX delivery-producing application-service entry must share the fair pre-pool gate" >&2
    exit 1
fi
echo "migration 0126 journals physical releases, audits a stopped cut-over, keeps ACKs lock-independent, and serializes producer admission before PgPool checkout"

# Migration 0127 turns competing XEP-0198 resume ownership into a committed,
# versioned event stream.  The event is only a wake hint: every consumer must
# subscribe and then immediately re-read the authority row, while the database
# remains the sole source of the retry boundary and claim decision.
sm_authority_event_migration="migrations/0127_sm_resume_authority_notifications.sql"
[ -f "$sm_authority_event_migration" ] || {
    echo "SM resume authority-event migration is missing: $sm_authority_event_migration" >&2
    exit 1
}
for required_fragment in \
    'ADD COLUMN state_version BIGINT NOT NULL DEFAULT 1' \
    'CREATE FUNCTION northstar_sm_state_version()' \
    'NEW.state_version := OLD.state_version + 1' \
    'CREATE FUNCTION northstar_sm_state_notify()' \
    "'northstar_sm_authority_v1'" \
    "'schema', TG_TABLE_SCHEMA" \
    "'session_id', changed_id" \
    "'state_version', changed_version" \
    'CREATE TRIGGER sm_resume_sessions_authority_version' \
    'CREATE TRIGGER sm_resume_sessions_authority_notify' \
    'old_connection_id UUID,state_version BIGINT,pending_reason TEXT' \
    'retry_at TIMESTAMPTZ,authority_now TIMESTAMPTZ,claimed_until TIMESTAMPTZ' \
    "WHEN live_pending AND claim_pending THEN 'live-and-claim-owner'" \
    "WHEN live_pending THEN 'live-owner'" \
    "ELSE 'claim-owner'" \
    'IF stream.expires_at<=authority_now THEN' \
    'retry_at := least(' \
    'stream.expires_at' \
    'stream.live_lease_until' \
    'stream.claimed_until' \
    "'northstar_sm_state_version()','private'" \
    "'northstar_sm_state_notify()','private'" \
    "'state_version','SELECT'" \
    'SM claim event projection ABI is inconsistent'
do
    if ! grep -Fq "$required_fragment" "$sm_authority_event_migration"; then
        echo "migration 0127 is missing SM event-authority invariant: $required_fragment" >&2
        exit 1
    fi
done
sm_notify_body=$(sed -n '/^CREATE FUNCTION northstar_sm_state_notify()/,/^\$\$;/p' "$sm_authority_event_migration")
if [ "$(printf '%s\n' "$sm_notify_body" | grep -Fc 'pg_catalog.json_build_object(')" -ne 1 ] \
   || [ "$(printf '%s\n' "$sm_notify_body" | grep -Ec "^[[:space:]]*'(schema|session_id|state_version)',")" -ne 3 ]; then
    echo "migration 0127 notification payload must contain exactly schema/session_id/state_version" >&2
    exit 1
fi
for forbidden_fragment in \
    "'full_jid'" \
    "'old_connection_id'" \
    "'peer_ip'" \
    "'token_hash'" \
    "'claim_token'"
do
    if printf '%s\n' "$sm_notify_body" | grep -Fq "$forbidden_fragment"; then
        echo "migration 0127 notification leaks an authority secret or identity: $forbidden_fragment" >&2
        exit 1
    fi
done

sm_resume_source=$(sed -n '/pub(crate) async fn resume_values_with_fast(/,/let claimed_bytes =/p' src/xmpp/protocol/sm.rs)
for forbidden_fragment in \
    'from_millis(10)' \
    'from_millis(500)' \
    'tokio::time::interval' \
    'tokio::time::timeout'
do
    if printf '%s\n' "$sm_resume_source" | grep -Fq "$forbidden_fragment"; then
        echo "SM resume Pending handling reintroduced fixed application polling/timeout: $forbidden_fragment" >&2
        exit 1
    fi
done
for required_source_fragment in \
    'try_reserve_claim()' \
    'drop(claim_capacity);' \
    '.subscribe_authority(pending.session_id)' \
    'continue;' \
    'subscription.acknowledge_probe(' \
    'wait_for_pending_authority(' \
    'pending.retry_at.min(ownership_horizon)' \
    'session.disconnect.cancel();'
do
    if ! printf '%s\n' "$sm_resume_source" | grep -Fq "$required_source_fragment"; then
        echo "SM resume Pending path is missing event-driven ownership invariant: $required_source_fragment" >&2
        exit 1
    fi
done
for required_broker_fragment in \
    'SM_AUTHORITY_NOTIFICATION_CHANNEL: &str = "northstar_sm_authority_v1"' \
    'max_connections(1)' \
    'PgListener::connect_with(&listener_pool)' \
    'notification = listener.try_recv()' \
    'authority.publish_listener_transition();' \
    'notification_sequence' \
    'borrow_and_update()' \
    'participants.fetch_sub(1, Ordering::AcqRel)' \
    '.participants' \
    '.fetch_add(1, Ordering::AcqRel)' \
    'Arc::ptr_eq(entry.get(), slot)' \
    'WorkerCriticality::Restartable'
do
    if ! grep -Fq "$required_broker_fragment" src/services/sm.rs; then
        echo "SM authority broker/listener is missing lifecycle invariant: $required_broker_fragment" >&2
        exit 1
    fi
done
echo "migration 0127 provides versioned commit notifications and SM Pending waits use exact event, route, cancellation, and database retry boundaries"

# Migration 0128 removes two false-busy/false-full correctness dependencies.
# Delivery orphan reclamation commits before producer admission, and MIX-PAM
# capacity is an exact owner-maintained global/per-account authority rather than
# COUNT(*) guarded by a non-waiting advisory lock.
mix_capacity_authority_migration="migrations/0128_mix_capacity_authorities.sql"
[ -f "$mix_capacity_authority_migration" ] || {
    echo "MIX capacity-authority migration is missing: $mix_capacity_authority_migration" >&2
    exit 1
}
for required_fragment in \
    'CREATE TABLE mix_pam_operation_capacity (' \
    'CREATE TABLE mix_pam_operation_user_capacity (' \
    'operation_count BIGINT NOT NULL CHECK (operation_count BETWEEN 0 AND max_operations)' \
    'max_operations BIGINT NOT NULL CHECK (max_operations = 10000)' \
    'max_per_user BIGINT NOT NULL CHECK (max_per_user = 64)' \
    'CREATE FUNCTION northstar_mix_pam_capacity_lock()' \
    'CREATE FUNCTION northstar_mix_pam_account_capacity_lock(' \
    'CREATE FUNCTION northstar_mix_pam_operation_capacity_insert()' \
    'CREATE FUNCTION northstar_mix_pam_operation_capacity_delete()' \
    'CREATE FUNCTION northstar_mix_pam_user_predelete_lock()' \
    'CREATE FUNCTION northstar_mix_pam_operation_insert(' \
    'expected_username TEXT' \
    'IF northstar_mix_pam_account_capacity_lock(' \
    'AND username = expected_username' \
    'FOR UPDATE;' \
    'expected_membership_state := CASE requested_operation' \
    'AND request_id = requested_remote_request_id' \
    'AND client_request_id = requested_client_request_id' \
    'AND requester_full_jid = requested_requester_full_jid' \
    'AND target_domain = requested_remote_domain' \
    'AND expires_at > clock_timestamp()' \
    'CREATE FUNCTION northstar_mix_pam_operation_prune(requested_limit BIGINT)' \
    'CREATE FUNCTION northstar_mix_pam_capacity_reconcile()' \
    'CREATE FUNCTION northstar_mix_delivery_capacity_reconcile()' \
    'UPDATE mix_pam_operation_capacity' \
    'INSERT INTO mix_pam_operation_user_capacity(user_id, operation_count)' \
    'PERFORM northstar_mix_pam_capacity_lock();' \
    'DELETE FROM mix_delivery_events event' \
    'PERFORM northstar_mix_delivery_capacity_drain();' \
    'SECURITY DEFINER SET search_path TO pg_catalog' \
    'REVOKE ALL ON TABLE mix_pam_operation_capacity,'
do
    if ! grep -Fq "$required_fragment" "$mix_capacity_authority_migration"; then
        echo "migration 0128 is missing MIX capacity invariant: $required_fragment" >&2
        exit 1
    fi
done
if grep -Fq 'pg_try_advisory_xact_lock' "$mix_capacity_authority_migration" \
   || grep -Fq 'mix-pam-operation-capacity-v1' src/db/mix.rs; then
    echo "MIX-PAM capacity must wait behind exact authority, not reject ordinary contention" >&2
    exit 1
fi
if [ "$(grep -Fc 'let _admission = self.pam_capacity_admission_guard().await;' src/services/mix.rs)" -ne 3 ]; then
    echo "MIX-PAM insert/prune entries must share one FIFO gate before PgPool checkout" >&2
    exit 1
fi
echo "migration 0128 commits delivery reclamation independently and gives MIX-PAM exact owner-maintained counters with pre-pool FIFO admission"

# Migration 0129 keeps collection-child quota enforcement at the database
# boundary without treating timestamp/no-op updates as a second child.  Actual
# edge moves are checked against the prospective graph, so a raw maintenance
# UPDATE cannot bypass quota, cycle, or depth invariants.
pubsub_edge_update_migration="migrations/0129_pubsub_collection_edge_update_semantics.sql"
[ -f "$pubsub_edge_update_migration" ] || {
    echo "PubSub collection-edge update migration is missing: $pubsub_edge_update_migration" >&2
    exit 1
}
for required_fragment in \
    'CREATE OR REPLACE FUNCTION check_pubsub_collection_edge()' \
    "IF TG_OP = 'UPDATE' THEN" \
    'old_collection_id := OLD.collection_node_id;' \
    'old_child_id := OLD.child_node_id;' \
    'old_collection_id = NEW.collection_node_id' \
    'old_child_id = NEW.child_node_id' \
    'WITH RECURSIVE graph_edges(collection_node_id, child_node_id) AS (' \
    'IS DISTINCT FROM (old_collection_id, old_child_id)' \
    'BEFORE INSERT OR UPDATE OF collection_node_id, child_node_id' \
    'pubsub collection child limit exceeded'
do
    if ! grep -Fq "$required_fragment" "$pubsub_edge_update_migration"; then
        echo "migration 0129 is missing PubSub collection-edge update invariant: $required_fragment" >&2
        exit 1
    fi
done
echo "migration 0129 preserves collection quota semantics for metadata updates and prospective edge moves"

# Migration 0130 bounds the physical unique-index tuple for canonical JID
# scopes without making a fixed-width digest authoritative.  Collision safety
# remains in the archive/account-deletion exact comparisons; the database index
# is solely an efficient candidate discriminator.
personal_admission_scope_lookup_migration="migrations/0130_personal_message_admission_scope_lookup.sql"
[ -f "$personal_admission_scope_lookup_migration" ] || {
    echo "personal-message admission scope lookup migration is missing: $personal_admission_scope_lookup_migration" >&2
    exit 1
}
for required_fragment in \
    'DROP INDEX personal_message_admission_identity_key;' \
    'CREATE UNIQUE INDEX personal_message_admission_identity_key' \
    "'northstar:personal-admission-actor-scope:v1:'" \
    "'northstar:personal-admission-target-scope:v1:'" \
    "'northstar:personal-admission-scope:v1:'" \
    'CREATE INDEX personal_message_admission_actor_scope_lookup_idx' \
    'CREATE INDEX personal_message_admission_target_scope_lookup_idx' \
    'identity_digest);'
do
    if ! grep -Fq "$required_fragment" "$personal_admission_scope_lookup_migration"; then
        echo "migration 0130 is missing bounded personal-admission identity invariant: $required_fragment" >&2
        exit 1
    fi
done
personal_admission_unique_index=$(sed -n \
    '/^CREATE UNIQUE INDEX personal_message_admission_identity_key/,/^        identity_digest);$/p' \
    "$personal_admission_scope_lookup_migration")
if ! printf '%s\n' "$personal_admission_unique_index" | grep -Fq 'pg_catalog.md5(' \
   || ! printf '%s\n' "$personal_admission_unique_index" | grep -Fq 'actor_scope::pg_catalog.text' \
   || ! printf '%s\n' "$personal_admission_unique_index" | grep -Fq 'target_scope::pg_catalog.text'; then
    echo "migration 0130 must use fixed-width actor and target scope discriminators in its identity index" >&2
    exit 1
fi
echo "migration 0130 bounds personal-admission identity and account-deletion lookup keys without making a digest authoritative"

# Migration 0131 moves generic upload-capacity contention into the database
# authority itself.  Do not reintroduce a caller-side wait or turn a held
# ledger into a stale/no-op result: the private primitive must return 55P03
# through NOWAIT and both direct capability and implicit trigger paths must
# acquire it before legacy capacity accounting.
upload_capacity_nowait_migration="migrations/0131_upload_capacity_nowait.sql"
[ -f "$upload_capacity_nowait_migration" ] || {
    echo "upload capacity NOWAIT migration is missing: $upload_capacity_nowait_migration" >&2
    exit 1
}
for required_fragment in \
    'CREATE FUNCTION northstar_upload_require_capacity_lock()' \
    'FOR UPDATE NOWAIT;' \
    'CREATE FUNCTION guard_upload_capacity_nowait()' \
    'BEFORE INSERT OR DELETE ON upload_slots' \
    'BEFORE UPDATE OF storage_object_key,storage_stage_key ON upload_slots' \
    'BEFORE INSERT OR DELETE ON upload_storage_jobs' \
    'BEFORE INSERT OR DELETE ON upload_cleanup_queue' \
    'PERFORM northstar_upload_require_capacity_lock();' \
    'REVOKE ALL ON FUNCTION %I.northstar_upload_require_capacity_lock() FROM %I' \
    'REVOKE ALL ON FUNCTION %I.guard_upload_capacity_nowait() FROM %I'
do
    if ! grep -Fq "$required_fragment" "$upload_capacity_nowait_migration"; then
        echo "migration 0131 is missing SQL-native upload capacity NOWAIT invariant: $required_fragment" >&2
        exit 1
    fi
done
if grep -Fq "SET LOCAL lock_timeout='50ms'" "$upload_capacity_nowait_migration"; then
    echo "migration 0131 must not reintroduce a caller-side timeout as generic capacity admission" >&2
    exit 1
fi
echo "migration 0131 makes generic upload-capacity contention owner-held, NOWAIT, and owner-only"

# Migration 0132 is deliberately forward-only: 0129 is already an immutable
# history entry, so its caller-selected search_path is repaired by pinning the
# installed invoker trigger helper in whatever application schema the migrator
# selected.  Keep the security mode invoker-scoped; this graph guard is not a
# privileged database capability.
pubsub_edge_path_migration="migrations/0132_pubsub_collection_edge_path.sql"
[ -f "$pubsub_edge_path_migration" ] || {
    echo "PubSub collection-edge search-path migration is missing: $pubsub_edge_path_migration" >&2
    exit 1
}
for required_fragment in \
    'current_schema()' \
    'check_pubsub_collection_edge() SECURITY INVOKER' \
    'SET search_path TO pg_catalog, %I, pg_temp' \
    'routine.proconfig=ARRAY[expected_path]::pg_catalog.text[]' \
    'AND NOT routine.prosecdef'
do
    if ! grep -Fq "$required_fragment" "$pubsub_edge_path_migration"; then
        echo "migration 0132 is missing PubSub collection-edge path invariant: $required_fragment" >&2
        exit 1
    fi
done
echo "migration 0132 pins the PubSub collection-edge trigger helper as a schema-local invoker routine"

# Versions 0001-0013 form the published 0.1.0 baseline that predates the 0.2.0
# development line. They are immutable: SQLx will reject changed content in an
# existing database, and this repository-side manifest catches the same mistake
# before a database is touched.
baseline_manifest="scripts/fixtures/migrations-0001-0013.sha256"
[ -f "$baseline_manifest" ] || {
    echo "published migration checksum manifest is missing: $baseline_manifest" >&2
    exit 1
}
manifest_paths=$(awk 'NF == 2 { print $2 }' "$baseline_manifest" | sort)
baseline_paths=$(find migrations -maxdepth 1 -type f -name '*.sql' -print \
    | awk -F/ '{ name=$NF; version=substr(name,1,4)+0; if (version >= 1 && version <= 13) print }' \
    | sort)
if [ "$manifest_paths" != "$baseline_paths" ]; then
    echo "published migration manifest must name exactly versions 0001-0013" >&2
    exit 1
fi
sha256sum --check --strict "$baseline_manifest"
echo "published migration 0001-0013 checksums match the immutable baseline"
