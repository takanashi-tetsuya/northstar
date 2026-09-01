#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
compose="$project_dir/docker-compose.yml"
init_script="$project_dir/deploy/postgres-init/010-northstar-roles.sh"
grant_policy="$project_dir/deploy/postgres-init/lib/reconcile-northstar-grants.sql"
grant_boundary="$project_dir/deploy/postgres-init/lib/verify-northstar-grant-boundary.sql"
grant_apply="$project_dir/deploy/postgres-init/lib/apply-northstar-grants.sql"
capability_manifest="$project_dir/deploy/postgres-init/lib/northstar-capability-manifest.sql"
migration_ledger_manifest="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
migration_ledger_generator="$project_dir/scripts/generate-database-migration-ledger.py"
capability_manifest_check="$project_dir/scripts/check-database-capability-manifest.py"
grant_runner="$project_dir/scripts/reconcile-database-grants.sh"
grant_image="$project_dir/deploy/database-grants.Dockerfile"
backup_image="$project_dir/deploy/backup.Dockerfile"
backup_runner="$project_dir/scripts/backup.sh"
role_attestation="$project_dir/src/db/role_attestation.rs"
db_module="$project_dir/src/db/mod.rs"
main_source="$project_dir/src/main.rs"
state_source="$project_dir/src/state.rs"
pie_source="$project_dir/src/pie.rs"
users_source="$project_dir/src/db/users.rs"
admin_commands_source="$project_dir/src/db/admin_commands.rs"
roster_source="$project_dir/src/db/roster.rs"
mix_source="$project_dir/src/db/mix.rs"
omemo_recovery_source="$project_dir/src/db/omemo_recovery.rs"
user_capability_migration="$project_dir/migrations/0108_user_command_capabilities.sql"
admin_cleanup_migration="$project_dir/migrations/0111_admin_session_cleanup_effects.sql"
cluster_authority_migration="$project_dir/migrations/0112_cluster_runtime_capacity_and_authority.sql"
upload_authority_migration="$project_dir/migrations/0113_upload_authority_capabilities.sql"
session_authority_migration="$project_dir/migrations/0114_session_authority_capabilities.sql"
admin_cleanup_fixture="$project_dir/scripts/admin-session-cleanup-db-wsl.sh"
restore_runner="$project_dir/scripts/restore-backup.sh"
disaster_fixture="$project_dir/scripts/backup-restore-wsl.sh"
role_runner="$project_dir/scripts/reconcile-database-roles.sh"
database_acceptance="$project_dir/scripts/database-role-boundary-db-ci.sh"
loopback_fixture="$project_dir/scripts/loopback-postgres-ci.sh"
secret_generator="$project_dir/scripts/create-production-secrets.sh"
release_preflight="$project_dir/scripts/release-preflight.sh"
ci_workflow="$project_dir/.github/workflows/ci.yml"

fail() {
  printf 'database role boundary check failed: %s\n' "$1" >&2
  exit 1
}

require_literal() {
  local file=$1
  local literal=$2
  local description=$3
  grep -Fq -- "$literal" "$file" || fail "$description"
}

service_block() {
  local service=$1
  awk -v target="$service" '
    $0 == "  " target ":" { inside = 1; print; next }
    inside && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
    inside { print }
  ' "$compose"
}

for file in "$compose" "$init_script" "$grant_policy" "$grant_boundary" "$grant_apply" \
  "$capability_manifest" "$migration_ledger_manifest" \
  "$migration_ledger_generator" "$capability_manifest_check" \
  "$grant_runner" "$grant_image" "$backup_image" "$backup_runner" \
  "$role_attestation" "$db_module" "$main_source" "$state_source" "$pie_source" \
  "$users_source" "$admin_commands_source" "$roster_source" "$mix_source" \
  "$omemo_recovery_source" "$user_capability_migration" "$admin_cleanup_migration" \
  "$cluster_authority_migration" "$upload_authority_migration" \
  "$session_authority_migration" \
  "$admin_cleanup_fixture" \
  "$restore_runner" "$role_runner" \
  "$disaster_fixture" "$database_acceptance" "$loopback_fixture" \
  "$secret_generator" "$release_preflight" \
  "$ci_workflow"; do
  [[ -f "$file" ]] || fail "required policy file is missing: ${file#$project_dir/}"
done
if command -v python3 >/dev/null 2>&1; then
  python3 "$capability_manifest_check"
elif command -v python >/dev/null 2>&1; then
  python "$capability_manifest_check"
else
  fail 'Python 3 is required for the database capability manifest check'
fi
require_literal "$ci_workflow" 'bash scripts/admin-session-cleanup-db-wsl.sh' \
  'CI does not run the isolated administrator cleanup effect fixture'
for boundary_probe in \
  'runtime cleanup effect direct read' \
  'runtime cleanup effect direct mutation' \
  'runtime cleanup capacity direct mutation' \
  'command issuer cleanup effect direct read' \
  'command issuer private cleanup helper'; do
  require_literal "$database_acceptance" "$boundary_probe" \
    "database role acceptance omits administrator cleanup boundary: $boundary_probe"
done
for protected_table in admin_session_cleanup_effects admin_session_cleanup_capacity; do
  require_literal "$grant_apply" "$protected_table" \
    "runtime administrator cleanup-ledger revocation is missing: $protected_table"
  require_literal "$role_attestation" "$protected_table" \
    "runtime role attestation omits private administrator cleanup ledger: $protected_table"
done

# PostgreSQL rewrites several SQL type and expression aliases only when they are
# unqualified.  Prefixing them with pg_catalog therefore looks defensive but is
# invalid SQL (for example pg_catalog.bigint and pg_catalog.coalesce(...)).
# Scan every executable migration/operations source, not just the files that
# happened to expose the original regression.
while IFS= read -r -d '' sql_source; do
  if grep -Eiq \
    'pg_catalog\.(bigint|boolean|integer|smallint|real|double[[:space:]]+precision|decimal|coalesce|nullif|greatest|least|current_date|current_time|current_timestamp|localtime|localtimestamp)([[:space:]]*\(|[^[:alnum:]_]|$)' \
    "$sql_source"; then
    fail "invalid schema-qualified PostgreSQL SQL alias in ${sql_source#$project_dir/}"
  fi
done < <(
  find "$project_dir/migrations" "$project_dir/deploy/postgres-init" "$project_dir/scripts" \
    -type f \( -name '*.sql' -o -name '*.sh' \) \
    ! -name 'check-database-role-boundaries.sh' -print0
)

require_literal "$compose" 'POSTGRES_USER: northstar_bootstrap' \
  'Compose must use the container-only bootstrap identity'
require_literal "$compose" \
  'POSTGRES_INITDB_ARGS: --auth-host=scram-sha-256 --auth-local=scram-sha-256' \
  'fresh database must use SCRAM for host and local bootstrap authentication'
if grep -Eq 'POSTGRES_USER:[[:space:]]*xmpp([[:space:]]|$)' "$compose"; then
  fail 'Compose must not create the application identity as PostgreSQL superuser'
fi
require_literal "$compose" \
  './deploy/postgres-init:/docker-entrypoint-initdb.d:ro' \
  'Compose must mount the complete init policy, including its private SQL library'

for secret in postgres_bootstrap_password northstar_migrator_password \
  northstar_runtime_password northstar_command_password northstar_backup_password migrator_database_url \
  runtime_database_url command_database_url backup_database_url; do
  require_literal "$compose" "  $secret:" "Compose secret is missing: $secret"
  require_literal "$secret_generator" "$secret" \
    "production secret generator does not manage: $secret"
done
for command_preflight_boundary in \
  'NORTHSTAR_COMMAND_PASSWORD_SECRET_FILE' \
  'COMMAND_DATABASE_URL_SECRET_FILE' \
  'check_secret_file "$command_password_path" northstar_command_password 70:70' \
  'check_secret_file "$command_database_url_path" command_database_url 10001:10001' \
  'verify_role_url "$command_database_url_path" "$command_password_path" northstar_commands command_database_url'; do
  require_literal "$release_preflight" "$command_preflight_boundary" \
    "production preflight is missing command-role boundary: $command_preflight_boundary"
done
require_literal "$release_preflight" \
  'Docker is required for --production because this mode validates the Compose deployment profile' \
  'production Compose preflight must fail closed when Docker is unavailable'
for capability in northstar_admin_command_issue_delete_cleanup \
  northstar_claim_admin_session_cleanup northstar_renew_admin_session_cleanup \
  northstar_retry_admin_session_cleanup northstar_complete_admin_session_cleanup \
  northstar_admin_session_cleanup_target_current \
  northstar_admin_session_cleanup_snapshot; do
  require_literal "$admin_cleanup_migration" "CREATE FUNCTION $capability" \
    "migration 0111 is missing administrator cleanup capability: $capability"
  require_literal "$grant_apply" "$capability" \
    "runtime SECURITY DEFINER allowlist is missing administrator cleanup capability: $capability"
  require_literal "$role_attestation" "$capability" \
    "runtime role attestation is missing administrator cleanup capability: $capability"
done
require_literal "$compose" 'NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets' \
  'Compose secret defaults must live outside the source checkout'
if grep -Fq -- 'deploy/secrets/' "$compose"; then
  fail 'Compose must not default runtime secrets into the source checkout'
fi
require_literal "$secret_generator" \
  'secret_dir=${NORTHSTAR_SECRET_DIR:-/etc/northstar/secrets}' \
  'secret generator must default to the external production secret root'
for boundary in validate_trusted_chain assert_secret_parent assert_secret_boundary \
  'lock_file="$secret_parent/.northstar-secrets.lock"' 'flock -n 9' "stat -c '%h'" \
  validate_hex_secret verify_database_url distinct_names \
  'trap cleanup_temporary_material EXIT' \
  'backup signing private key is not canonical' \
  'backup age identity file must contain exactly one canonical line'; do
  require_literal "$secret_generator" "$boundary" \
    "secret generator is missing fail-closed boundary: $boundary"
done
lock_line=$(grep -nF 'exec 9>>"$lock_file"' "$secret_generator" | cut -d: -f1)
secret_dir_write_line=$(grep -nF 'install -d -m 0700 -o 0 -g 0 -- "$secret_dir"' "$secret_generator" | cut -d: -f1)
[[ -n "$lock_line" && -n "$secret_dir_write_line" && "$lock_line" -lt "$secret_dir_write_line" ]] \
  || fail 'secret generator must lock its verified parent before the first secret-directory write'
if grep -Fq 'install -d -m 0700 -o 0 -g 0 -- "$secret_parent"' "$secret_generator"; then
  fail 'secret generator must refuse to create an unlocked parent directory'
fi

postgres_service=$(service_block postgres)
migrate_service=$(service_block migrate)
grant_service=$(service_block database-grants)
xmpp_service=$(service_block xmpp)
backup_service=$(service_block backup)
restore_service=$(service_block restore)

[[ "$postgres_service" == *'/run/secrets/postgres_bootstrap_password'* ]] \
  || fail 'PostgreSQL must consume its bootstrap password through a secret file'
for secret in northstar_migrator_password northstar_runtime_password northstar_command_password northstar_backup_password; do
  [[ "$postgres_service" == *"/run/secrets/$secret"* ]] \
    || fail "fresh-volume initialization cannot read $secret"
done

[[ "$migrate_service" == *'/run/secrets/migrator_database_url'* ]] \
  || fail 'migration service must use migrator_database_url'
[[ "$migrate_service" == *'entrypoint: ["/usr/local/bin/xmpp-server"]'* \
   && "$migrate_service" == *'command: ["migrate"]'* ]] \
  || fail 'migration service must bypass the normal writable-directory entrypoint'
for forbidden in postgres_bootstrap_password northstar_migrator_password \
  northstar_runtime_password northstar_command_password northstar_backup_password runtime_database_url \
  command_database_url backup_database_url; do
  [[ "$migrate_service" != *"$forbidden"* ]] \
    || fail "migration service must not receive $forbidden"
done

[[ "$grant_service" == *'/run/secrets/migrator_database_url'* ]] \
  || fail 'post-migration grant service must use migrator_database_url'
for forbidden in postgres_bootstrap_password northstar_migrator_password \
  northstar_runtime_password northstar_command_password northstar_backup_password runtime_database_url \
  command_database_url backup_database_url; do
  [[ "$grant_service" != *"$forbidden"* ]] \
    || fail "post-migration grant service must not receive $forbidden"
done
[[ "$xmpp_service" == *'database-grants:'* ]] \
  || fail 'long-lived application must wait for post-migration ACL reconciliation'
require_literal "$grant_image" \
  'COPY --chown=10001:10001 --chmod=0444 migrations ./migrations' \
  'grant image must be coupled to the migration tree'

[[ "$xmpp_service" == *'DATABASE_URL_FILE: /run/secrets/runtime_database_url'* ]] \
  || fail 'long-lived application must use runtime_database_url'
[[ "$xmpp_service" == *'ADMIN_COMMAND_DATABASE_URL_FILE: /run/secrets/command_database_url'* ]] \
  || fail 'long-lived application must isolate XEP-0133 issuance in command_database_url'
for forbidden in postgres_bootstrap_password northstar_migrator_password \
  northstar_command_password northstar_backup_password migrator_database_url backup_database_url; do
  [[ "$xmpp_service" != *"$forbidden"* ]] \
    || fail "long-lived application must not receive $forbidden"
done

[[ "$backup_service" == *'/run/secrets/backup_database_url'* ]] \
  || fail 'backup service must use the read-only backup_database_url'
for forbidden in postgres_bootstrap_password northstar_migrator_password \
  northstar_runtime_password northstar_command_password northstar_backup_password migrator_database_url \
  runtime_database_url command_database_url; do
  [[ "$backup_service" != *"$forbidden"* ]] \
    || fail "backup service must not receive $forbidden"
done

[[ "$restore_service" == *'/run/secrets/migrator_database_url'* ]] \
  || fail 'restore service must use the explicit migrator capability'
for forbidden in postgres_bootstrap_password northstar_migrator_password \
  northstar_runtime_password northstar_command_password northstar_backup_password runtime_database_url \
  command_database_url backup_database_url; do
  [[ "$restore_service" != *"$forbidden"* ]] \
    || fail "restore service must not receive $forbidden"
done

require_literal "$init_script" "readonly bootstrap_role='northstar_bootstrap'" \
  'fresh init bootstrap role changed unexpectedly'
for role in northstar_migrator northstar_runtime northstar_commands northstar_backup; do
  require_literal "$init_script" "$role" "fresh init role is missing: $role"
  require_literal "$role_runner" "$role" "existing-volume role policy is missing: $role"
done
require_literal "$init_script" \
  'NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' \
  'fresh init does not explicitly remove workload cluster privileges'
require_literal "$role_runner" \
  'NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' \
  'existing-volume reconciliation does not remove workload cluster privileges'
require_literal "$role_runner" '--connection-password-file' \
  'existing-volume reconciliation does not separate connection and bootstrap passwords'
require_literal "$role_runner" 'export PGPASSWORD="$connection_password"' \
  'existing-volume connection must use its dedicated password variable'
require_literal "$role_runner" \
  'export NORTHSTAR_BOOTSTRAP_PASSWORD="$bootstrap_password"' \
  'new bootstrap role must use its dedicated password variable'
require_literal "$role_runner" \
  "ORDER BY CASE WHEN relation.relkind = 'S' THEN 1 ELSE 0 END, relation.oid" \
  'existing-volume ownership transfer must move tables before owned sequences'
require_literal "$role_runner" \
  "'audit_log','legal_holds','legal_hold_personal_archives'" \
  'role audit must carry an explicit immutable-history privilege manifest'
require_literal "$role_runner" \
  'runtime role can execute a non-allowlisted SECURITY DEFINER routine' \
  'role audit must reject runtime execution of unreviewed definer routines'
require_literal "$role_runner" \
  'command role does not have the exact session capability set' \
  'role audit must enforce the exact command-issuer routine manifest'
require_literal "$role_runner" \
  'command role has application relation privilege' \
  'role audit must reject every command-role relation privilege'
require_literal "$init_script" 'CONNECTION LIMIT 2' \
  'fresh init does not bound backup database connections'
require_literal "$init_script" 'CONNECTION LIMIT 4' \
  'fresh init does not bound migrator database connections'
require_literal "$init_script" 'CONNECTION LIMIT 64' \
  'fresh init does not bound runtime database connections'
require_literal "$init_script" 'CONNECTION LIMIT 8' \
  'fresh init does not bound XEP-0133 command database connections'
require_literal "$main_source" 'db::attest_migrator_role(&pool).await?;' \
  'migrator command does not attest its database owner identity'
require_literal "$db_module" "pg_advisory_lock(" \
  'migration command does not serialize against ACL reconciliation'
require_literal "$db_module" "northstar-database-role-policy-v1" \
  'migration command uses a different database policy lock key'
require_literal "$grant_policy" "northstar-database-role-policy-v1" \
  'ACL reconciliation uses a different database policy lock key'
require_literal "$main_source" 'db::attest_runtime_role(&pool).await?;' \
  'long-lived server does not attest its runtime database identity'
require_literal "$state_source" 'crate::db::attest_admin_command_role(&command_pool).await?;' \
  'isolated XEP-0133 command pool does not attest its exact role'
require_literal "$main_source" 'db::pin_public_application_schema(pool_options)' \
  'production migrator/runtime pools do not override DSN search_path options'
require_literal "$state_source" \
  'crate::db::pin_public_application_schema(omemo_recovery_pool_options)' \
  'isolated OMEMO recovery pool does not inherit the production schema pin'
require_literal "$pie_source" 'crate::db::pin_public_application_schema(pool_options)' \
  'PIE worker pool does not override DSN search_path options'
require_literal "$role_attestation" \
  "set_config('search_path','public',FALSE)" \
  'production pool schema pin is missing or transaction-local'
require_literal "$role_attestation" "role.rolname='northstar_runtime'" \
  'runtime role attestation is not bound to the exact workload identity'
require_literal "$role_attestation" 'embedded migration ledger contains an unreviewed version gap' \
  'runtime embedded ledger accepts an unreviewed migration-version gap'
require_literal "$role_attestation" "session_user=current_user" \
  'database role attestation does not reject SET ROLE identity masquerading'
require_literal "$role_attestation" "current_schemas(FALSE)=ARRAY['public'::pg_catalog.name]" \
  'production role attestation does not pin the exact application schema'
require_literal "$backup_runner" "current_user='northstar_backup'" \
  'backup does not attest its exact read-only database identity'
require_literal "$backup_runner" 'attest_repository_migration_ledger' \
  'backup does not reject a missing/unknown/failed/tampered release ledger'
require_literal "$backup_runner" 'northstar-database-role-policy-v1' \
  'backup ledger attestation is not fenced against migration/ACL reconciliation'
require_literal "$backup_runner" '__POLICY_LOCK_OK__' \
  'backup does not prove acquisition of the database policy fence'
require_literal "$backup_runner" 'len(versions) != len(set(versions))' \
  'backup accepts a duplicated repository migration manifest'
require_literal "$grant_policy" '\ir verify-northstar-grant-boundary.sql' \
  'post-migration policy must reuse the shared boundary assertions'
require_literal "$grant_policy" '\ir apply-northstar-grants.sql' \
  'post-migration policy must reuse the shared atomic grant body'
require_literal "$grant_policy" '\ir northstar-capability-manifest.sql' \
  'post-migration policy must load the canonical capability manifest'
require_literal "$grant_policy" '\ir northstar-migration-ledger-manifest.sql' \
  'post-migration policy must load the repository SHA-384 migration ledger'
require_literal "$grant_boundary" 'Northstar workload roles must not participate in role memberships' \
  'shared grant boundary does not reject role memberships'
require_literal "$grant_runner" '--set=allow_bootstrap=false' \
  'ordinary post-migration reconciliation must reject bootstrap/superuser URLs'
require_literal "$grant_runner" '--set=grant_phase=exact' \
  'ordinary post-migration reconciliation must require the complete 0114/0115 boundary'
require_literal "$role_runner" '--set=grant_phase=auto' \
  'legacy role reconciliation must select a ledger-attested grant phase'
require_literal "$project_dir/deploy/postgres-init/010-northstar-roles.sh" \
  '--set=grant_phase=bootstrap' \
  'fresh role initialization must use the empty-database bootstrap phase'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON DATABASE :"database_name" FROM PUBLIC CASCADE;' \
  'database PUBLIC privileges are not revoked'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC CASCADE;' \
  'schema PUBLIC privileges are not revoked'
require_literal "$grant_apply" "default_acl.defaclnamespace=0" \
  'global default ACLs are not included in exact convergence'
require_literal "$grant_apply" "default_acl.defaclobjtype NOT IN ('r','S','f','T','n')" \
  'PostgreSQL 17 schema default ACLs are not included in exact convergence'
require_literal "$grant_apply" "FROM (VALUES ('f'::\"char\"),('T'::\"char\"))" \
  'missing routine/type default-ACL rows are not rejected as unsafe built-ins'
require_literal "$grant_apply" 'ledger_matches_prepare' \
  'pre-boundary phase is not checked against the exact repository ledger'
if grep -Fq 'ON COMMIT DROP' "$migration_ledger_manifest"; then
  fail 'migration ledger manifest disappears before autocommit role audits can use it'
fi
require_literal "$grant_apply" 'ledger_matches_exact' \
  'post-boundary phase is not checked against the exact repository ledger'
require_literal "$grant_apply" 'pg_catalog.octet_length(checksum)=48' \
  'migration ledger does not require exact SHA-384 checksum width'
require_literal "$grant_apply" 'northstar_pre_boundary_acl_set_is_owner_only' \
  'bootstrap/legacy preparation does not prove an owner-only zero-capability catalog'
require_literal "$grant_apply" 'partial Northstar capability boundary' \
  '0114/0115 partial migration state is not rejected'
require_literal "$grant_apply" \
  'GRANT SELECT ON ALL TABLES IN SCHEMA public' \
  'backup role is not granted read-only table access'
require_literal "$grant_apply" \
  'REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public' \
  'runtime/backup routine execution must start from a fail-closed empty set'
require_literal "$grant_apply" \
  'northstar_canonical_capability_manifest_is_exact' \
  'grant reconciliation does not compare catalog/runtime/command sets to the canonical manifest'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s) FROM %I' \
  'grant reconciliation does not erase arbitrary stale SECURITY DEFINER grantees'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM %I' \
  'grant reconciliation does not erase arbitrary stale relation grantees'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM %I' \
  'grant reconciliation does not erase arbitrary stale sequence grantees'
require_literal "$grant_apply" \
  'northstar_relation_grantee_set_is_exact' \
  'grant reconciliation does not verify the exact relation/column grantee set'
require_literal "$role_runner" \
  'unexpected explicit relation ACL grantee' \
  'role audit does not report arbitrary relation grantees'
require_literal "$role_runner" \
  'unexpected explicit column ACL grantee' \
  'role audit does not report arbitrary column grantees'
require_literal "$role_runner" \
  'repository migration ledger differs by version, description, success, or SHA-384 checksum' \
  'role audit does not reject missing/unknown/failed/tampered migration rows'
require_literal "$grant_apply" \
  'AND NOT routine.prosecdef' \
  'runtime routine reconciliation must grant only SECURITY INVOKER routines by default'
require_literal "$grant_apply" \
  'northstar_transfer_cluster_muc_outbox(uuid,uuid,uuid,uuid,int8,uuid,int8,text)' \
  'runtime SECURITY DEFINER allowlist is missing its exact MUC handoff signature'
require_literal "$grant_apply" \
  'northstar_release_legal_hold(uuid,uuid,text,uuid)' \
  'runtime SECURITY DEFINER allowlist is missing the exact legal-hold release capability'
require_literal "$grant_apply" \
  'REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER' \
  'runtime users-table direct DML revocation is missing'
for protected_table in admin_service_messages federation_runtime_rules admin_service_control; do
  require_literal "$grant_apply" "$protected_table" \
    "runtime XEP-0133 control-state revocation is missing: $protected_table"
  require_literal "$role_attestation" "$protected_table" \
    "runtime role attestation omits protected XEP-0133 state: $protected_table"
done
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES (%s) ON TABLE %I.%I FROM PUBLIC, %I, %I, %I' \
  'grant reconciliation must erase legacy column ACLs before rebuilding roles'
require_literal "$grant_apply" \
  "has_any_column_privilege(:'runtime_role',relation.oid,'UPDATE')" \
  'runtime users-table postcondition must reject column-level UPDATE authority'
for capability in northstar_user_register northstar_user_create_bootstrap_admin \
  northstar_user_clear_scram_sha1 northstar_user_apply_login \
  northstar_user_change_password_api northstar_user_change_password_stream \
  northstar_user_set_status_api northstar_user_bump_roster_version \
  northstar_user_consume_recovery_generation northstar_user_quiesce_deletion \
  northstar_user_delete_quiesced northstar_admin_command_authorize_claim \
  northstar_admin_command_create_user northstar_admin_command_reset_user_password \
  northstar_admin_command_user_lifecycle northstar_admin_command_delete_user \
  northstar_admin_command_replace_users northstar_admin_command_record_announcement \
  northstar_admin_command_set_service_message \
  northstar_admin_command_replace_federation_rules \
  northstar_admin_command_service_control \
  northstar_admin_service_control_poll; do
  require_literal "$user_capability_migration" "CREATE FUNCTION $capability" \
    "migration 0108 is missing typed capability: $capability"
  require_literal "$grant_apply" "$capability" \
    "runtime SECURITY DEFINER allowlist is missing: $capability"
  require_literal "$role_attestation" "$capability" \
    "runtime role attestation is missing: $capability"
done
for capability in northstar_admin_command_create_session \
  northstar_admin_command_finish_session northstar_admin_command_complete_immediate_read \
  northstar_admin_command_begin_execution northstar_admin_command_renew_claim \
  northstar_admin_command_release_claim northstar_admin_command_complete_read_claim \
  northstar_admin_command_cleanup; do
  require_literal "$user_capability_migration" "CREATE FUNCTION $capability" \
    "migration 0108 is missing command-issuer capability: $capability"
  require_literal "$grant_apply" "$capability" \
    "command role allowlist is missing: $capability"
  require_literal "$role_attestation" "$capability" \
    "command role attestation is missing: $capability"
done
if grep -Eiq 'EXECUTE[[:space:]]+[^;]*(requested_|caller_)|format\([^)]*(requested_|caller_)|current_setting\(.northstar\..*authority' \
  "$user_capability_migration"; then
  fail 'user command capabilities must not use caller-directed SQL or custom-GUC authority'
fi
require_literal "$users_source" 'SELECT northstar_user_register(' \
  'registration does not use the typed database capability'
require_literal "$users_source" 'SELECT northstar_user_apply_login(' \
  'login publication does not use the typed database capability'
require_literal "$users_source" 'SELECT northstar_user_change_password_api(' \
  'REST password rotation does not use the bearer-fenced database capability'
require_literal "$users_source" 'SELECT northstar_user_change_password_stream(' \
  'XMPP password rotation does not use the generation-fenced database capability'
require_literal "$admin_commands_source" 'SELECT northstar_admin_command_user_lifecycle(' \
  'XEP-0133 lifecycle mutation does not consume an execution claim'
require_literal "$roster_source" 'SELECT northstar_user_bump_roster_version($1)' \
  'roster mutation still writes users directly'
require_literal "$mix_source" 'SELECT northstar_user_bump_roster_version($1)' \
  'MIX roster mutation still writes users directly'
require_literal "$omemo_recovery_source" 'SELECT northstar_user_consume_recovery_generation($1,$2,$3)' \
  'OMEMO recovery does not use the exact bearer/generation capability'
require_literal "$pie_source" 'production PIE import requires MIGRATOR_DATABASE_URL_FILE' \
  'offline PIE import was not moved behind the stopped migrator boundary'
require_literal "$grant_apply" \
  'cluster_muc_delivery_handoffs' \
  'runtime handoff-history mutation revocation is missing'
require_literal "$grant_apply" \
  'REVOKE ALL PRIVILEGES ON FUNCTIONS FROM :"runtime_role", :"command_role", :"backup_role" CASCADE;' \
  'future migrator functions must not default to runtime execution'
require_literal "$grant_apply" \
  "relation.relname IN ('_sqlx_migrations','jid_identity_migrations')" \
  'runtime migration-ledger write revocation is missing'
require_literal "$grant_apply" \
  'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public' \
  'runtime sequence privileges are not bounded to nextval/currval access'
if grep -Eiq 'GRANT[^;]*UPDATE[^;]*ON (ALL )?SEQUENCES' "$grant_apply"; then
  fail 'runtime must not receive sequence UPDATE/setval authority'
fi
if grep -Fq 'GRANT EXECUTE ON ALL ROUTINES IN SCHEMA public' "$grant_apply"; then
  fail 'runtime must not receive blanket execution on current routines'
fi
if grep -Fq 'GRANT EXECUTE ON FUNCTIONS TO :"runtime_role";' "$grant_apply"; then
  fail 'runtime must not receive default execution on future functions'
fi
for backup_guard in \
  "has_any_column_privilege(current_user,relation.oid,'INSERT')" \
  "has_any_column_privilege(current_user,relation.oid,'UPDATE')" \
  "has_any_column_privilege(current_user,relation.oid,'REFERENCES')" \
  "has_sequence_privilege(current_user,sequence.oid,'USAGE')" \
  "has_sequence_privilege(current_user,sequence.oid,'UPDATE')"; do
  require_literal "$backup_runner" "$backup_guard" \
    "backup role attestation omits writable ACL guard: $backup_guard"
done

[[ $(grep -Fc \
  'pg_catalog.jsonb_array_length(requested_joined_rooms)>256' \
  "$session_authority_migration") -eq 2 ]] \
  || fail 'SM create/update capabilities must both enforce the 256-room snapshot bound'
[[ $(grep -Fc \
  'pg_catalog.jsonb_array_length(requested_directed_presence)>1024' \
  "$session_authority_migration") -eq 2 ]] \
  || fail 'SM create/update capabilities must both enforce the 1024-directed-presence bound'
[[ $(grep -Fc \
  'pg_catalog.octet_length(requested_last_presence) NOT BETWEEN 1 AND 1048576' \
  "$session_authority_migration") -eq 2 ]] \
  || fail 'SM create/update capabilities must both enforce the 1 MiB presence bound'
require_literal "$session_authority_migration" 'unexpected_relation_acl AS (' \
  'session catalog health does not inspect arbitrary relation grantees'
require_literal "$session_authority_migration" 'unexpected_column_acl AS (' \
  'session catalog health does not inspect arbitrary sensitive-column grantees'
for sensitive_column in token_hash claim_token peer_ip; do
  require_literal "$session_authority_migration" "'$sensitive_column'" \
    "session catalog health omits sensitive SM column: $sensitive_column"
done
if grep -Eq '^[[:space:]]*(BEGIN|COMMIT);' "$grant_apply"; then
  fail 'shared grant body must stay transaction-neutral for atomic restore reuse'
fi
grant_policy_flat=$(sed '/^[[:space:]]*--/d' "$grant_apply" | tr '\r\n' '  ')
if grep -Eiq 'ALTER DEFAULT PRIVILEGES[^;]*GRANT([[:space:]]|$)[^;]*(runtime_role|command_role|backup_role)' \
  <<<"$grant_policy_flat"; then
  fail 'future migration objects must remain owner-only until exact reconciliation'
fi
if grep -Eiq \
  '(^|;)[[:space:]]*GRANT[^;]*(CREATE|INSERT|UPDATE|DELETE|TRUNCATE|TRIGGER|EXECUTE)([[:space:]]|,)[^;]*backup_role' \
  <<<"$grant_policy_flat"; then
  fail 'backup role policy contains a write or create grant'
fi
if grep -Eiq '(^|;)[[:space:]]*GRANT[^;]*CREATE([[:space:]]|,)[^;]*runtime_role' \
  <<<"$grant_policy_flat"; then
  fail 'runtime role policy contains a create grant'
fi

require_literal "$backup_image" \
  'deploy/postgres-init/lib/verify-northstar-grant-boundary.sql' \
  'restore image does not contain the shared grant-boundary assertions'
require_literal "$backup_image" \
  'deploy/postgres-init/lib/apply-northstar-grants.sql' \
  'restore image does not contain the shared atomic grant body'
require_literal "$backup_image" \
  'deploy/postgres-init/lib/northstar-capability-manifest.sql' \
  'restore image does not contain the canonical capability manifest'
require_literal "$backup_image" \
  'deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql' \
  'restore image does not contain the repository migration ledger manifest'
require_literal "$grant_image" \
  'deploy/postgres-init/lib/northstar-capability-manifest.sql' \
  'grant image does not contain the canonical capability manifest'
require_literal "$grant_image" \
  'deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql' \
  'grant image does not contain the repository migration ledger manifest'
require_literal "$disaster_fixture" 'apply_repository_migrations northstar_backup_source' \
  'backup/restore drill does not install the real complete migration chain'
if grep -Fq 'INSERT INTO _sqlx_migrations VALUES (13, TRUE)' "$disaster_fixture"; then
  fail 'backup/restore drill still uses a synthetic version-13 migration ledger'
fi
require_literal "$restore_runner" \
  'bash "$script_dir/validate-backup-dump-local.sh"' \
  'restore preflight must use an isolated local PostgreSQL instance'
if grep -Fq '"${pg_client[@]}" createdb' "$restore_runner" \
   || grep -Fq '"${pg_client[@]}" dropdb' "$restore_runner"; then
  fail 'restore must not create or drop validation databases on the target cluster'
fi
if grep -Fq 'pg_terminate_backend' "$restore_runner"; then
  fail 'the non-superuser restore must not terminate target database sessions'
fi
if grep -Fq 'pg_database_owner' "$restore_runner"; then
  fail 'restore must create schema public as the verified migrator owner'
fi
require_literal "$restore_runner" \
  "EXECUTE format('CREATE SCHEMA public AUTHORIZATION %I', current_user);" \
  'restore does not recreate schema public as the verified migrator owner'
require_literal "$restore_runner" \
  'cat "$grant_apply_sql" >&"$db_session_in"' \
  'restore does not apply the shared ACL policy inside replacement'
require_literal "$restore_runner" \
  'cat "$capability_manifest_sql" >&"$db_session_in"' \
  'restore does not load the canonical capability manifest inside replacement'
grant_apply_line=$(grep -nF 'cat "$grant_apply_sql" >&"$db_session_in"' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
capability_manifest_line=$(grep -nF \
  'cat "$capability_manifest_sql" >&"$db_session_in"' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
post_grant_commit_line=$(awk -v start="$grant_apply_line" \
  'NR > start && /printf .*COMMIT;/ { print NR; exit }' "$restore_runner")
[[ -n "$capability_manifest_line" && -n "$grant_apply_line" \
   && "$capability_manifest_line" -lt "$grant_apply_line" \
   && -n "$post_grant_commit_line" \
   && "$grant_apply_line" -lt "$post_grant_commit_line" ]] \
  || fail 'restore must load capability manifest, converge ACLs, then commit replacement'
require_literal "$disaster_fixture" \
  'BACKUP_SECURITY_POLICY=production bash "$project_dir/scripts/backup.sh"' \
  'disaster-recovery fixture does not exercise the production backup policy'
require_literal "$disaster_fixture" \
  '"postgresql://$backup_role:$backup_password@/northstar_backup_source?host=$encoded_socket"' \
  'production backup fixture does not use the read-only backup identity'
require_literal "$disaster_fixture" \
  'BACKUP_SECURITY_POLICY=production bash "$project_dir/scripts/restore-backup.sh"' \
  'disaster-recovery fixture does not exercise the production restore policy'
require_literal "$disaster_fixture" '__RESTORE_PEER_SURVIVED__' \
  'disaster-recovery fixture does not prove restore leaves an existing peer alive'

require_literal "$ci_workflow" 'database-role-boundary:' \
  'CI must contain a database-backed role-boundary job'
require_literal "$loopback_fixture" '--network host' \
  'CI runtime database fixture must share the runner network namespace'
require_literal "$loopback_fixture" '-c listen_addresses=127.0.0.1' \
  'CI runtime database fixture must bind PostgreSQL only to IPv4 loopback'
require_literal "$loopback_fixture" \
  'SELECT pg_catalog.host(pg_catalog.inet_server_addr())' \
  'CI runtime database fixture must attest a loopback host address without an inet netmask'
require_literal "$ci_workflow" 'bash scripts/database-role-boundary-db-ci.sh' \
  'CI does not execute the database-backed role-boundary acceptance script'
require_literal "$database_acceptance" 'NORTHSTAR_DATABASE_ROLE_CI' \
  'database-backed acceptance test lacks its explicit destructive-test gate'
require_literal "$database_acceptance" \
  'python3 scripts/generate-database-migration-ledger.py --check' \
  'database acceptance does not reject a stale repository migration ledger before mutation'
for quoted_replay_boundary in \
  'quoted-schema-migration.sql' \
  '[[ "$(sed -n '\''1p'\'' "$migration_path")" == '\''-- no-transaction'\'' ]]' \
  '--set=migration_path="$migration_path" --file "$quoted_migration_driver"' \
  'psql_as "$migrator_role" "$migrator_password" --single-transaction'; do
  require_literal "$database_acceptance" "$quoted_replay_boundary" \
    "quoted-schema migration replay omits transaction boundary: $quoted_replay_boundary"
done
require_literal "$database_acceptance" '--demote-legacy-xmpp' \
  'database-backed acceptance test does not exercise the legacy-role cutover'
require_literal "$database_acceptance" \
  'cargo run --quiet --locked --bin rust-xmpp-server -- migrate' \
  'database-backed acceptance test does not run the real migrator command'
require_literal "$database_acceptance" \
  'bash scripts/reconcile-database-grants.sh' \
  'database-backed acceptance test omits post-migration grant reconciliation'
for denied_boundary in \
  'runtime CREATE in public' \
  'runtime TEMPORARY object creation' \
  'runtime ownership change' \
  'runtime trigger disable' \
  'runtime SQLx migration-ledger forgery' \
  'runtime identity migration-ledger forgery' \
  'runtime sequence setval' \
  'runtime direct users INSERT' \
  'runtime direct users UPDATE' \
  'runtime direct users DELETE' \
  'runtime SM ${secret_column} column read' \
  'runtime role escalation' \
  'runtime direct handoff history mutation' \
  'runtime forged audit retention marker' \
  'runtime forged hold-snapshot retention marker' \
  'runtime forged governance-export retention marker' \
  'runtime forged cluster-MUC retention marker' \
  'runtime offline upload authority maintenance' \
  'runtime upload job capacity trigger execution' \
  'runtime upload cleanup capacity trigger execution' \
  'runtime cluster MUC fence trigger execution' \
  'backup table write' \
  'backup application routine execution' \
  'backup sequence allocation' \
  'backup TEMPORARY object creation'; do
  require_literal "$database_acceptance" "$denied_boundary" \
    "database-backed acceptance test omits denial: $denied_boundary"
done
require_literal "$database_acceptance" \
  'immutable history and elevated capabilities are exact' \
  'database-backed acceptance must verify the immutable-history manifest'
require_literal "$database_acceptance" \
  'SECURITY DEFINER schema, owner, or execution allowlist drifted' \
  'database-backed acceptance must verify the exact SECURITY DEFINER boundary'
require_literal "$database_acceptance" \
  'cluster MUC handoff history is not runtime read-only' \
  'database-backed acceptance must verify read-only handoff history'
require_literal "$database_acceptance" \
  'users table is not runtime read-only' \
  'database-backed acceptance must verify read-only user authority'
require_literal "$database_acceptance" \
  '0112-0114 authority table/column ACL manifest drifted' \
  'database-backed acceptance must verify exact cluster/upload/session authority ACLs'
require_literal "$database_acceptance" \
  'SM exact/subnet policy accepted a snapshot with NULL stored peer_ip' \
  'database-backed acceptance must reject NULL stored peer IP under bound policies'
require_literal "$database_acceptance" \
  'canonical verifier did not report the seeded stale routine grantee' \
  'database-backed acceptance must prove arbitrary definer grantee drift is detected'
require_literal "$database_acceptance" \
  'grant reconciliation retained a stale SECURITY DEFINER grantee' \
  'database-backed acceptance must prove arbitrary definer grantee drift is removed'
require_literal "$database_acceptance" \
  'canonical verifier did not report the seeded stale relation grantee' \
  'database-backed acceptance must prove arbitrary relation grantee drift is detected'
require_literal "$database_acceptance" \
  'grant reconciliation retained a stale relation or sensitive-column grantee' \
  'database-backed acceptance must prove arbitrary relation grantee drift is removed'
require_literal "$database_acceptance" \
  'session authority catalog reports non-canonical relation/column ACLs' \
  'database-backed acceptance must run the session catalog ACL health check'
require_literal "$database_acceptance" \
  'runtime SM create capability oversized joined-room snapshot' \
  'database-backed acceptance must call the SM create capability with oversized state'
require_literal "$database_acceptance" \
  'runtime SM snapshot capability accepted or persisted oversized state' \
  'database-backed acceptance must reject all oversized SM snapshot projections'
require_literal "$database_acceptance" \
  'SM strict same-device policy accepted a legacy NULL stored device ID' \
  'database-backed acceptance must reject legacy NULL device IDs in strict mode'
require_literal "$database_acceptance" \
  'SM strict same-device policy accepted a NULL claimant device ID' \
  'database-backed acceptance must reject NULL claimant device IDs in strict mode'
require_literal "$database_acceptance" \
  'SM compatibility mode rejected a legacy NULL stored device ID' \
  'database-backed acceptance must retain explicit non-strict legacy compatibility'
require_literal "$database_acceptance" \
  'non-administrator promotion was not rejected by the command capability' \
  'database-backed acceptance must prove non-admin promotion is rejected'
require_literal "$database_acceptance" \
  'concurrent auth-generation command did not produce one exact winner' \
  'database-backed acceptance must prove generation compare-and-swap under concurrency'

printf '%s\n' 'database role and secret-isolation static checks passed'
