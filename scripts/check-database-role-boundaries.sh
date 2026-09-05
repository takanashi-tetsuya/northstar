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
postgres_runner="$project_dir/scripts/run-postgres.py"
role_attestation="$project_dir/src/db/role_attestation.rs"
db_module="$project_dir/src/db/mod.rs"
main_source="$project_dir/src/main.rs"
state_source="$project_dir/src/state.rs"
pie_source="$project_dir/src/pie.rs"
users_source="$project_dir/src/db/users.rs"
admin_commands_source="$project_dir/src/db/admin_commands.rs"
roster_source="$project_dir/src/db/roster.rs"
mix_source="$project_dir/src/db/mix.rs"
muc_source="$project_dir/src/db/muc.rs"
muc_protocol_source="$project_dir/src/xmpp/protocol/muc.rs"
omemo_recovery_source="$project_dir/src/db/omemo_recovery.rs"
user_capability_migration="$project_dir/migrations/0108_user_command_capabilities.sql"
admin_cleanup_migration="$project_dir/migrations/0111_admin_session_cleanup_effects.sql"
cluster_authority_migration="$project_dir/migrations/0112_cluster_runtime_capacity_and_authority.sql"
upload_authority_migration="$project_dir/migrations/0113_upload_authority_capabilities.sql"
session_authority_migration="$project_dir/migrations/0114_session_authority_capabilities.sql"
admin_cleanup_fixture="$project_dir/scripts/admin-session-cleanup-db-wsl.sh"
stateful_database_manifest="$project_dir/scripts/stateful-database-ci.sh"
restore_runner="$project_dir/scripts/restore-backup.sh"
dump_validator="$project_dir/scripts/validate-backup-dump-local.sh"
disaster_fixture="$project_dir/scripts/backup-restore-wsl.sh"
integration_fixture="$project_dir/scripts/integration-wsl.py"
message_pow_fixture="$project_dir/scripts/message-pow-wire-wsl.py"
role_runner="$project_dir/scripts/reconcile-database-roles.sh"
database_acceptance="$project_dir/scripts/database-role-boundary-db-ci.sh"
database_acceptance_local="$project_dir/scripts/database-role-boundary-wsl.sh"
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

shell_function_block() {
  local file=$1 function_name=$2
  awk -v declaration="$function_name() {" '
    $0 == declaration { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
  ' "$file"
}

for file in "$compose" "$init_script" "$grant_policy" "$grant_boundary" "$grant_apply" \
  "$capability_manifest" "$migration_ledger_manifest" \
  "$migration_ledger_generator" "$capability_manifest_check" \
  "$grant_runner" "$grant_image" "$backup_image" "$backup_runner" "$postgres_runner" \
  "$role_attestation" "$db_module" "$main_source" "$state_source" "$pie_source" \
  "$users_source" "$admin_commands_source" "$roster_source" "$mix_source" \
  "$muc_source" "$muc_protocol_source" "$omemo_recovery_source" \
  "$user_capability_migration" "$admin_cleanup_migration" \
  "$cluster_authority_migration" "$upload_authority_migration" \
  "$session_authority_migration" \
  "$admin_cleanup_fixture" \
  "$stateful_database_manifest" \
  "$restore_runner" "$dump_validator" "$role_runner" \
  "$disaster_fixture" "$message_pow_fixture" "$database_acceptance" "$loopback_fixture" \
  "$database_acceptance_local" \
  "$secret_generator" "$release_preflight" \
  "$ci_workflow"; do
  [[ -f "$file" ]] || fail "required policy file is missing: ${file#$project_dir/}"
done
for postgres_runner_contract in \
  'os.memfd_create("northstar-pgpass", flags=0)' \
  'os.fchmod(descriptor, 0o600)' \
  'os.set_inheritable(descriptor, True)' \
  'environment["PGPASSFILE"] = f"/proc/self/fd/{descriptor}"' \
  'os.execvpe(command[0], command, environment)'; do
  require_literal "$postgres_runner" "$postgres_runner_contract" \
    "PostgreSQL client wrapper lacks exact-process/memory-only credential contract: $postgres_runner_contract"
done
if grep -Eq '\b(subprocess\.(run|Popen)|tempfile\.(TemporaryDirectory|NamedTemporaryFile))\b' \
    "$postgres_runner"; then
  fail 'PostgreSQL client wrapper must exec the exact client and must not persist a password file'
fi
if command -v python3 >/dev/null 2>&1; then
  python3 "$capability_manifest_check"
elif command -v python >/dev/null 2>&1; then
  python "$capability_manifest_check"
else
  fail 'Python 3 is required for the database capability manifest check'
fi
require_literal "$ci_workflow" 'bash scripts/stateful-database-ci.sh "${{ matrix.shard }}"' \
  'CI does not route stateful database coverage through the checked shard entrypoint'
require_literal "$stateful_database_manifest" \
  'admin-session-cleanup|Admin session cleanup database|480|admin-session-cleanup-db-wsl.sh' \
  'the stateful database suite manifest does not route the isolated administrator cleanup effect fixture through its unique suite id'
require_literal "$stateful_database_manifest" \
  'phase=database_suite_result' \
  'the stateful database suite manifest does not emit a terminal result for every invoked suite'
for boundary_probe in \
  'runtime cleanup effect direct read' \
  'runtime cleanup effect direct mutation' \
  'runtime cleanup capacity direct mutation' \
  'command issuer cleanup effect direct read' \
  'command issuer private cleanup helper'; do
  require_literal "$database_acceptance" "$boundary_probe" \
    "database role acceptance omits administrator cleanup boundary: $boundary_probe"
done

# The local role-boundary test is intentionally destructive.  It must never
# select then release a TCP port before PostgreSQL owns it: a private Unix
# socket directory gives it a collision-free transport and keeps it unable to
# touch the developer's shared TCP PostgreSQL service.
require_literal "$database_acceptance_local" "listen_addresses=''" \
  'local database role fixture does not disable TCP listeners'
require_literal "$database_acceptance_local" 'unix_socket_permissions=0700' \
  'local database role fixture does not restrict its private Unix socket'
require_literal "$database_acceptance_local" 'PGHOST="$socket_dir"' \
  'local database role fixture does not pass its private Unix socket to the acceptance runner'
if grep -Fq 'allocate-test-ports.py' "$database_acceptance_local"; then
  fail 'local database role fixture still uses a released TCP port allocator'
fi
require_literal "$database_acceptance" "database_transport='private-unix-socket'" \
  'database role acceptance does not recognize its exact private Unix socket transport'
require_literal "$database_acceptance" 'host=${encoded_database_host}' \
  'database role acceptance does not encode the private Unix socket in the migrator URL'
for protected_table in admin_session_cleanup_effects admin_session_cleanup_capacity; do
  require_literal "$capability_manifest" \
    "('$protected_table',FALSE,FALSE,FALSE,FALSE,'0111')" \
    "canonical manifest omits private administrator cleanup ledger: $protected_table"
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
for maintenance_policy in \
  'ALTER DATABASE postgres OWNER TO :"bootstrap_role";' \
  'ALTER DATABASE postgres WITH ALLOW_CONNECTIONS true CONNECTION LIMIT -1 IS_TEMPLATE false;' \
  'REVOKE ALL PRIVILEGES ON DATABASE postgres FROM PUBLIC;' \
  "'REVOKE ALL PRIVILEGES ON DATABASE postgres FROM %I CASCADE'" \
  'GRANT CONNECT ON DATABASE postgres TO :"migrator_role";'; do
  require_literal "$init_script" "$maintenance_policy" \
    "fresh init is missing maintenance database policy: $maintenance_policy"
  require_literal "$role_runner" "$maintenance_policy" \
    "existing-volume reconciliation is missing maintenance database policy: $maintenance_policy"
done
require_literal "$role_runner" \
  'migrator lacks explicit postgres maintenance CONNECT' \
  'database role audit does not verify the restore maintenance capability'
require_literal "$role_runner" \
  'PUBLIC retains postgres maintenance privilege:' \
  'database role audit does not reject PUBLIC maintenance database access'
require_literal "$role_runner" \
  'unexpected postgres maintenance ACL:' \
  'database role audit does not reject non-migrator maintenance access'
require_literal "$role_runner" \
  'postgres maintenance database is missing or has unsafe identity/configuration' \
  'database role audit does not verify maintenance owner and connection policy'
require_literal "$role_runner" \
  "granted.rolname IN (" \
  'database role reconciliation does not inspect protected role memberships'
for membership_file in "$init_script" "$role_runner"; do
  require_literal "$membership_file" \
    ":'bootstrap_role', :'migrator_role', :'runtime_role'" \
    'bootstrap role is missing from bidirectional membership convergence'
  require_literal "$membership_file" \
    "REVOKE %I FROM %I CASCADE" \
    'protected role membership convergence does not remove delegated grant chains'
done
require_literal "$role_runner" \
  "rolname NOT IN (:'bootstrap_role','xmpp')" \
  'role audit does not fail unknown login superusers while allowing explicit legacy migration'
unexpected_superuser_query=$(sed -n \
  '/unexpected_superusers=.*<<'"'"'PSQL'"'"'/,/^PSQL$/p' "$role_runner")
if [[ "$unexpected_superuser_query" == *'rolcanlogin'* \
   || "$unexpected_superuser_query" != *'WHERE rolsuper'* ]]; then
  fail 'role audit must detect privileged NOLOGIN superusers as well as login superusers'
fi
require_literal "$role_runner" \
  'warning: legacy database role xmpp retains authority' \
  'role audit does not surface residual legacy superuser/login/membership authority'
reconcile_call_count=$(grep -Ec \
  '^[[:space:]]*bash scripts/reconcile-database-roles\.sh ' "$database_acceptance")
reconcile_exception_count=$(grep -Fc -- \
  '--allow-external-superuser "$control_role"' "$database_acceptance")
[[ "$reconcile_call_count" -gt 0 \
   && "$reconcile_call_count" -eq "$reconcile_exception_count" ]] \
  || fail 'every isolated role-CI reconciliation must explicitly name its external control superuser'
for role_ci_contract in \
  'the CI PostgreSQL maintenance database is not the disposable canonical service' \
  'ALTER DATABASE postgres OWNER TO northstar_ci_control;' \
  'failed to restore the disposable CI maintenance database boundary' \
  "COMMENT ON ROLE xmpp IS :'database_marker';" \
  'GRANT northstar_runtime TO northstar_ci_stale_grantee WITH ADMIN OPTION;' \
  'role reconciliation retained a protected role membership or delegated grant chain'; do
  require_literal "$database_acceptance" "$role_ci_contract" \
    "isolated role-CI ownership/membership lifecycle is missing: $role_ci_contract"
done
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
for immutable_relation in \
  "('audit_log',TRUE,TRUE,FALSE,FALSE,'0001')" \
  "('legal_holds',TRUE,TRUE,FALSE,FALSE,'0087')" \
  "('legal_hold_personal_archives',TRUE,TRUE,FALSE,FALSE,'0087')"; do
  require_literal "$capability_manifest" "$immutable_relation" \
    'canonical runtime relation manifest must preserve immutable-history privileges'
done
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
require_literal "$capability_manifest" \
  'CREATE TEMPORARY TABLE northstar_runtime_relation_manifest' \
  'canonical manifest omits the complete runtime relation policy'
require_literal "$grant_apply" \
  'northstar_runtime_relation_capability_manifest_is_exact' \
  'grant reconciliation does not prove exact runtime table privileges from the canonical manifest'
require_literal "$role_runner" \
  'pg_temp.northstar_runtime_relation_manifest expected' \
  'existing-volume role audit does not consume the canonical runtime relation manifest'
require_literal "$role_attestation" \
  'attest_runtime_relation_capability_manifest(pool).await?' \
  'startup role attestation does not consume the canonical runtime relation manifest'
if grep -Fq 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public' "$grant_apply"; then
  fail 'runtime table reconciliation must not use broad DML plus an exception list'
fi
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
require_literal "$capability_manifest" \
  "('users',TRUE,FALSE,FALSE,FALSE,'0001')" \
  'runtime users-table capability is not read-only in the canonical manifest'
for protected_relation in \
  "('admin_service_messages',TRUE,FALSE,FALSE,FALSE,'0048')" \
  "('federation_runtime_rules',TRUE,FALSE,FALSE,FALSE,'0048')" \
  "('admin_service_control',TRUE,FALSE,FALSE,FALSE,'0052')"; do
  require_literal "$capability_manifest" "$protected_relation" \
    'canonical runtime relation manifest must preserve read-only XEP-0133 control state'
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
require_literal "$dump_validator" \
  "readonly migrator_role='northstar_migrator'" \
  'isolated dump validation does not define the production migrator identity'
require_literal "$dump_validator" \
  'CREATE ROLE northstar_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB' \
  'isolated dump validation does not recreate the unprivileged role boundary'
require_literal "$dump_validator" \
  '--owner="$migrator_role"' \
  'isolated dump validation database is not owned by the migrator'
require_literal "$dump_validator" \
  'pg_restore -h "$socket_dir" -U "$migrator_role" -d "$validation_database"' \
  'isolated dump validation still restores as a bootstrap superuser'
require_literal "$dump_validator" \
  '--no-owner --no-acl --single-transaction' \
  'isolated dump validation is not an atomic owner-independent restore'
require_literal "$dump_validator" \
  '--set allow_bootstrap=false --set grant_phase=exact' \
  'isolated dump validation does not require the exact current grant lifecycle'
require_literal "$dump_validator" \
  '--file "$grant_reconcile_sql"' \
  'isolated dump validation does not execute the canonical grant authority'
if grep -Fq 'pg_restore -h "$socket_dir" -U postgres' "$dump_validator"; then
  fail 'isolated dump validation must not hide authority drift behind superuser restore'
fi
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
  'cat "$grant_apply_sql" >&"$worker_in"' \
  'restore does not apply the shared ACL policy inside the isolated replacement worker'
require_literal "$restore_runner" \
  'cat "$capability_manifest_sql" >&"$worker_in"' \
  'restore does not load the canonical capability manifest inside the isolated replacement worker'
grant_apply_line=$(grep -nF 'cat "$grant_apply_sql" >&"$worker_in"' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
capability_manifest_line=$(grep -nF \
  'cat "$capability_manifest_sql" >&"$worker_in"' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
post_grant_commit_line=$(awk -v start="$grant_apply_line" \
  'NR > start && /printf .*COMMIT;/ { print NR; exit }' "$restore_runner")
[[ -n "$capability_manifest_line" && -n "$grant_apply_line" \
   && "$capability_manifest_line" -lt "$grant_apply_line" \
   && -n "$post_grant_commit_line" \
   && "$grant_apply_line" -lt "$post_grant_commit_line" ]] \
  || fail 'restore must load capability manifest, converge ACLs, then commit replacement'
for restore_session_contract in \
  '[[ "$1" =~ ^(control|coordinator|primary|compensation)$ ]]' \
  'declare -A psql_session_state=()' \
  'declare -A psql_session_input_anchor_fd_registry=()' \
  'declare -A psql_session_output_anchor_fd_registry=()' \
  'psql_session_state[$label]=preparing' \
  'psql_session_pid_registry[$label]="$child_pid"' \
  'psql_session_state[$label]=starting' \
  'psql_session_input_fd_registry[$label]="$session_input"' \
  'psql_session_output_fd_registry[$label]="$session_output"' \
  'psql_session_state[$label]=open' \
  'start_psql_session control control_session_pid control_session_in control_session_out maintenance' \
  'start_psql_session coordinator target_coordinator_pid target_coordinator_in' \
  'start_psql_session primary primary_worker_pid primary_worker_in primary_worker_out target' \
  'start_psql_session compensation compensation_worker_pid' \
  'mkfifo -m 0600 -- "$input_fifo" "$output_fifo"' \
  'exec {input_anchor}<>"$input_fifo"' \
  'psql_session_input_anchor_fd_registry[$label]="$input_anchor"' \
  'exec {output_anchor}<>"$output_fifo"' \
  'psql_session_output_anchor_fd_registry[$label]="$output_anchor"' \
  'close_psql_session_anchors "$label"' \
  'psql_session_anchors_are_closed "$label"' \
  'forget_psql_session_input_anchor_fd "$label"' \
  'forget_psql_session_output_anchor_fd "$label"' \
  '"${psql_session_input_anchor_fd_registry[$anchor_label]:-}"' \
  '"${psql_session_output_anchor_fd_registry[$anchor_label]:-}"' \
  'for anchor_label in control coordinator primary compensation; do' \
  'if [[ "$connection_scope" == maintenance ]]; then' \
  'psql_connection_arguments=(--dbname=postgres)' \
  'exec "${pg_client[@]}" psql "${psql_connection_arguments[@]}"' \
  "trap 'deferred_start_signal=INT' INT" \
  "trap 'deferred_start_signal=TERM' TERM" \
  'trap - INT TERM' \
  "trap 'exit 130' INT" \
  "trap 'exit 143' TERM" \
  'kill -s "$deferred_start_signal" "$BASHPID"' \
  'close_inherited_parent_fds || exit 125' \
  '[[ -e "/proc/$BASHPID/fd/$fd" ]]' \
  'exec {fd}>&-' \
  'dispose_starting_psql_session "$label"' \
  'forget_psql_session_input_fd "$label"' \
  'forget_psql_session_pid "$label"' \
  'forget_psql_session_output_fd "$label"' \
  'clear_psql_session_registration "$label"' \
  'for label in primary compensation coordinator control; do' \
  'local input_open=false output_open=false anchors_closed=true cleanup_ok=true' \
  '&& "$anchors_closed" == true ]]; then' \
  'close_db_sessions || cleanup_ok=false' \
  'run_pg_client_without_parent_fds pg_dump' \
  'run_pg_client_without_parent_fds pg_restore "$replacement_dump"' \
  'primary_worker_command "$grant_check_sql" "$grant_check_output"' \
  'control_session_command "$sql_file" "$output_file"' \
  'target_coordinator_command "$barrier_sql" "$barrier_output"' \
  '[[ "$control_database" == postgres && "$control_backend_pid" =~ ^[0-9]+$ ]]' \
  'discover_target_coordinator_identity || return 1' \
  'acquire_target_coordination_locks || return 1' \
  'verify_primary_target_identity || return 1' \
  'verify_compensation_target_identity || return 1' \
  '[[ "$worker_database" =~ ^[A-Za-z0-9_.-]{1,63}$' \
  '&& "$worker_database" != postgres' \
  '&& "$worker_database" != template0' \
  '&& "$worker_database" != template1' \
  '[[ -n "$target_database" && "$worker_database" == "$target_database" ]]' \
  '[[ "$control_backend_pid" != "$target_coordinator_backend_pid"' \
  '&& "$target_coordinator_backend_pid" != "$primary_backend_pid" ]]' \
  '&& "$primary_backend_pid" != "$compensation_backend_pid" ]]' \
  "WHERE datname = :'target_db'" \
  'WHERE pid NOT IN (:coordinator_pid, :primary_pid, :compensation_pid)' \
  'allowed_sessions != 3' \
  'restore_transaction_active=true' \
  'settle_active_restore_transaction' \
  'abort_active_restore_worker_for_cleanup' \
  'Closing stdin is the transaction-safe interrupt.' \
  'refusing to release the database fence while a replacement transaction is unsettled' \
  'refusing to release the database fence while the restore outcome is unknown' \
  'refusing to release the database fence without a committed replacement generation' \
  'refusing to release the database fence before the original generation is restored' \
  '[[ "$database_fence_active" == true ]]' \
  'SET LOCAL synchronous_commit TO on;' \
  "pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0))" \
  'pg_catalog.pg_current_xact_id()::text' \
  "pg_catalog.pg_xact_status((:'restore_xid')::pg_catalog.xid8)" \
  'journal_append database-transaction-intent "$transaction_kind" "$label"' \
  'journal_append database-transaction-outcome "$settled_kind" "$settled_label"' \
  'record_restore_transaction_result' \
  'incoming_restore_xid="$transaction_xid"' \
  'rollback_restore_xid="$transaction_xid"' \
  '"$transaction_xid" != "$incoming_restore_xid"' \
  'replace_database_from_dump "$payload_dir/database.dump" restored exact' \
  'replace_database_from_dump "$rollback_dump" rollback auto' \
  '"target-database=$target_database"' \
  '"maintenance-control-pid=$control_backend_pid"' \
  '"target-coordinator-pid=$target_coordinator_backend_pid"' \
  '"primary-executor-pid=$primary_backend_pid"' \
  '"compensation-executor-pid=$compensation_backend_pid"'; do
  require_literal "$restore_runner" "$restore_session_contract" \
    "restore control/worker outcome contract is missing: $restore_session_contract"
done
for restore_authority_contract in \
  'control:control_session_pid:control_session_in:control_session_out:maintenance' \
  'coordinator:target_coordinator_pid:target_coordinator_in:target_coordinator_out:target' \
  'primary:primary_worker_pid:primary_worker_in:primary_worker_out:target' \
  'compensation:compensation_worker_pid:compensation_worker_in:compensation_worker_out:target' \
  'control_session_command() {' \
  'target_coordinator_command() {' \
  'wait_for_restore_transaction_barrier() {' \
  'record_restore_transaction_result() {' \
  'read_restore_worker_identity() {' \
  'discover_target_coordinator_identity() {' \
  'verify_primary_target_identity() {' \
  'verify_compensation_target_identity() {' \
  'acquire_target_coordination_locks() {' \
  'acquire_primary_policy_lock() {' \
  'release_primary_policy_lock_after_fence() {' \
  'establish_restore_database_authorities() {' \
  'set_target_database_connections() {' \
  'activate_target_database_fence() {' \
  'release_target_database_fence() {'; do
  require_literal "$restore_runner" "$restore_authority_contract" \
    "restore responsibility boundary is missing: $restore_authority_contract"
done
for retired_restore_outcome_contract in \
  'northstar.restore_commit' \
  'pg_db_role_setting' \
  'read_target_restore_outcome' \
  'clear_target_restore_outcome' \
  'restore_outcome_clear_started' \
  'restore_outcome_cleared' \
  'incoming_outcome_marker' \
  'rollback_outcome_marker'; do
  if grep -Fq "$retired_restore_outcome_contract" "$restore_runner"; then
    fail "restore must use PostgreSQL XID status, not retired outcome-marker state: $retired_restore_outcome_contract"
  fi
done
if grep -Eq \
    'ALTER[[:space:]]+DATABASE.*(SET|RESET)[[:space:]]+northstar\.|(set_config|current_setting)[[:space:]]*\([^)]*northstar\.restore' \
    "$restore_runner"; then
  fail 'restore must not reintroduce a database-level custom GUC as transaction outcome authority'
fi
for ambiguous_restore_symbol in db_session_command read_restore_outcome \
  clear_restore_outcome set_database_connections activate_database_fence \
  release_database_fence initialize_restore_worker; do
  if grep -Eq "(^|[^A-Za-z0-9_])${ambiguous_restore_symbol}([^A-Za-z0-9_]|$)" \
      "$restore_runner"; then
    fail "restore retains ambiguous control/data-plane symbol: $ambiguous_restore_symbol"
  fi
done

target_lock_block=$(shell_function_block "$restore_runner" acquire_target_coordination_locks)
policy_lock_block=$(shell_function_block "$restore_runner" acquire_primary_policy_lock)
policy_unlock_block=$(shell_function_block "$restore_runner" release_primary_policy_lock_after_fence)
barrier_block=$(shell_function_block "$restore_runner" wait_for_restore_transaction_barrier)
connection_fence_block=$(shell_function_block "$restore_runner" set_target_database_connections)
release_fence_block=$(shell_function_block "$restore_runner" release_target_database_fence)
transaction_result_block=$(shell_function_block "$restore_runner" record_restore_transaction_result)
identity_read_block=$(shell_function_block "$restore_runner" read_restore_worker_identity)
target_identity_block=$(shell_function_block "$restore_runner" discover_target_coordinator_identity)
barrier_function_line=$(grep -nF 'wait_for_restore_transaction_barrier() {' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
barrier_begin_line=$(awk -v start="$barrier_function_line" \
  'NR > start && /^}/ { exit } NR > start && /printf .*BEGIN;/ { print NR; exit }' \
  "$restore_runner")
barrier_lock_line=$(awk -v start="$barrier_function_line" \
  'NR > start && /^}/ { exit } NR > start && /pg_advisory_xact_lock/ { print NR; exit }' \
  "$restore_runner")
barrier_status_line=$(awk -v start="$barrier_function_line" \
  'NR > start && /^}/ { exit } NR > start && /pg_xact_status/ { print NR; exit }' \
  "$restore_runner")
barrier_commit_line=$(awk -v start="$barrier_function_line" \
  'NR > start && /^}/ { exit } NR > start && /printf .*COMMIT;/ { print NR; exit }' \
  "$restore_runner")
[[ "$target_lock_block" == *'target_coordinator_command "$lock_sql" "$lock_output"'* \
   && "$target_lock_block" != *'control_session_command'* \
   && "$target_lock_block" != *'primary_worker_command'* ]] \
  || fail 'target-local maintenance lock must be routed only to the target coordinator'
[[ "$policy_lock_block" == *'primary_worker_command "$lock_sql" "$lock_output"'* \
   && "$policy_lock_block" != *'target_coordinator_command'* \
   && "$policy_lock_block" != *'control_session_command'* \
   && "$policy_unlock_block" == *'primary_worker_command "$unlock_sql" "$unlock_output"'* \
   && "$policy_unlock_block" == *'[[ "$database_fence_active" == true ]]'* \
   && "$policy_unlock_block" != *'target_coordinator_command'* \
   && "$policy_unlock_block" != *'control_session_command'* ]] \
  || fail 'database policy lock ownership must remain on the primary executor through the hard fence'
[[ "$barrier_block" == *'target_coordinator_command "$barrier_sql" "$barrier_output"'* \
   && "$barrier_block" != *'control_session_command'* \
   && "$barrier_block" == *"pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0))"* \
   && "$barrier_block" == *"pg_catalog.pg_xact_status((:'restore_xid')::pg_catalog.xid8)"* \
   && "$connection_fence_block" == *'control_session_command "$sql_file" "$output_file"'* \
   && "$connection_fence_block" != *'target_coordinator_command'* ]] \
  || fail 'restore transaction status/barrier and connection-fence ownership crossed their database scopes'
[[ -n "$barrier_function_line" && -n "$barrier_begin_line" \
   && -n "$barrier_lock_line" && -n "$barrier_status_line" \
   && -n "$barrier_commit_line" \
   && "$barrier_function_line" -lt "$barrier_begin_line" \
   && "$barrier_begin_line" -lt "$barrier_lock_line" \
   && "$barrier_lock_line" -lt "$barrier_status_line" \
   && "$barrier_status_line" -lt "$barrier_commit_line" ]] \
  || fail 'restore must acquire the transaction barrier before querying pg_xact_status in that same transaction'
[[ "$transaction_result_block" == *'incoming_restore_xid="$transaction_xid"'* \
   && "$transaction_result_block" == *'rollback_restore_xid="$transaction_xid"'* \
   && "$transaction_result_block" == *'"$transaction_xid" != "$incoming_restore_xid"'* \
   && "$transaction_result_block" == *'database_generation_state="replacement"'* \
   && "$transaction_result_block" == *'database_generation_state="original"'* \
   && "$release_fence_block" == *'"$incoming_restore_status" != committed'* \
   && "$release_fence_block" == *'"$database_generation_state" != replacement'* \
   && "$release_fence_block" == *'"$database_generation_state" != original'* \
   && "$release_fence_block" == *'"$rollback_restore_status" != committed'* ]] \
  || fail 'incoming/rollback XIDs, generation state and fence release must remain one explicit state machine'
[[ "$identity_read_block" == *'local -n pid_result="$5" database_result="$6"'* \
   && "$identity_read_block" == *'local init_sql="$work_dir/$label-worker-init.sql" parsed_database parsed_pid'* \
   && "$identity_read_block" == *'pid_result="$parsed_pid"'* \
   && "$identity_read_block" == *'database_result="$parsed_database"'* \
   && "$identity_read_block" != *'printf -v'* ]] \
  || fail 'restore worker identity outputs must use namerefs and non-shadowing parsed locals'
[[ "$target_identity_block" == *'&& "$worker_database" != postgres'* \
   && "$target_identity_block" == *'&& "$worker_database" != template0'* \
   && "$target_identity_block" == *'&& "$worker_database" != template1'* ]] \
  || fail 'restore target identity must reject every PostgreSQL maintenance/template database'
if grep -Fq 'coproc ' "$restore_runner"; then
  fail 'restore must not depend on Bash single-coprocess bookkeeping for its four live PostgreSQL sessions'
fi
session_prepare_line=$(grep -nF 'psql_session_state[$label]=preparing' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_namespace_line=$(grep -nF 'mkdir -m 0700 -- "$fifo_dir"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_fifo_line=$(grep -nF 'mkfifo -m 0600 -- "$input_fifo" "$output_fifo"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_input_anchor_open_line=$(grep -nF 'exec {input_anchor}<>"$input_fifo"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_input_anchor_register_line=$(grep -nF \
  'psql_session_input_anchor_fd_registry[$label]="$input_anchor"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_output_anchor_open_line=$(grep -nF 'exec {output_anchor}<>"$output_fifo"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_output_anchor_register_line=$(grep -nF \
  'psql_session_output_anchor_fd_registry[$label]="$output_anchor"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_spawn_line=$(grep -nF ') <"$input_fifo" >"$output_fifo" &' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_child_close_inherited_line=$(awk -v start="$session_output_anchor_register_line" \
  'NR > start && /close_inherited_parent_fds \|\| exit 125/ { print NR; exit }' \
  "$restore_runner")
session_child_exec_line=$(awk -v start="$session_child_close_inherited_line" \
  'NR > start && /exec "\$\{pg_client\[@\]\}" psql/ { print NR; exit }' \
  "$restore_runner")
session_pid_line=$(grep -nF 'psql_session_pid_registry[$label]="$child_pid"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_restore_int_line=$(awk -v start="$session_pid_line" \
  "NR > start && /trap 'exit 130' INT/ { print NR; exit }" "$restore_runner")
session_restore_term_line=$(awk -v start="$session_restore_int_line" \
  "NR > start && /trap 'exit 143' TERM/ { print NR; exit }" "$restore_runner")
session_replay_signal_line=$(grep -nF 'kill -s "$deferred_start_signal" "$BASHPID"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_input_open_line=$(grep -nF 'exec {session_input}>"$input_fifo"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_input_register_line=$(grep -nF \
  'psql_session_input_fd_registry[$label]="$session_input"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_output_open_line=$(grep -nF 'exec {session_output}<"$output_fifo"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_output_register_line=$(grep -nF \
  'psql_session_output_fd_registry[$label]="$session_output"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
session_anchor_close_line=$(awk -v start="$session_output_register_line" \
  'NR > start && /close_psql_session_anchors "\$label"/ { print NR; exit }' \
  "$restore_runner")
session_anchor_empty_line=$(awk -v start="$session_anchor_close_line" \
  'NR > start && /psql_session_anchors_are_closed "\$label"/ { print NR; exit }' \
  "$restore_runner")
session_unlink_line=$(awk -v start="$session_anchor_empty_line" \
  'NR > start && /remove_psql_session_namespace "\$label"/ { print NR; exit }' \
  "$restore_runner")
session_open_line=$(grep -nF 'psql_session_state[$label]=open' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
first_session_start_call=$(grep -nE '^establish_restore_database_authorities$' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
script_int_trap_line=$(awk -v limit="$first_session_start_call" \
  '$0 == "trap '\''exit 130'\'' INT" && NR < limit { line = NR } END { print line }' \
  "$restore_runner")
script_term_trap_line=$(awk -v limit="$first_session_start_call" \
  '$0 == "trap '\''exit 143'\'' TERM" && NR < limit { line = NR } END { print line }' \
  "$restore_runner")
[[ -n "$session_prepare_line" && -n "$session_namespace_line" \
   && -n "$session_fifo_line" \
   && -n "$session_input_anchor_open_line" \
   && -n "$session_input_anchor_register_line" \
   && -n "$session_output_anchor_open_line" \
   && -n "$session_output_anchor_register_line" \
   && -n "$session_child_close_inherited_line" \
   && -n "$session_child_exec_line" \
   && -n "$session_spawn_line" && -n "$session_pid_line" \
   && -n "$session_restore_int_line" && -n "$session_restore_term_line" \
   && -n "$session_replay_signal_line" \
   && -n "$session_input_open_line" && -n "$session_input_register_line" \
   && -n "$session_output_open_line" && -n "$session_output_register_line" \
   && -n "$session_anchor_close_line" \
   && -n "$session_anchor_empty_line" \
   && -n "$session_unlink_line" && -n "$session_open_line" \
   && -n "$first_session_start_call" && -n "$script_int_trap_line" \
   && -n "$script_term_trap_line" \
   && "$script_int_trap_line" -lt "$script_term_trap_line" \
   && "$script_term_trap_line" -lt "$first_session_start_call" \
   && "$session_prepare_line" -lt "$session_namespace_line" \
   && "$session_namespace_line" -lt "$session_fifo_line" \
   && "$session_fifo_line" -lt "$session_input_anchor_open_line" \
   && "$session_input_anchor_open_line" -lt "$session_input_anchor_register_line" \
   && "$session_input_anchor_register_line" -lt "$session_output_anchor_open_line" \
   && "$session_output_anchor_open_line" -lt "$session_output_anchor_register_line" \
   && "$session_output_anchor_register_line" -lt "$session_child_close_inherited_line" \
   && "$session_child_close_inherited_line" -lt "$session_child_exec_line" \
   && "$session_child_exec_line" -lt "$session_spawn_line" \
   && "$session_spawn_line" -lt "$session_pid_line" \
   && "$session_pid_line" -lt "$session_restore_int_line" \
   && "$session_restore_int_line" -lt "$session_restore_term_line" \
   && "$session_restore_term_line" -lt "$session_replay_signal_line" \
   && "$session_replay_signal_line" -lt "$session_input_open_line" \
   && "$session_input_open_line" -lt "$session_input_register_line" \
   && "$session_input_register_line" -lt "$session_output_open_line" \
   && "$session_output_open_line" -lt "$session_output_register_line" \
   && "$session_output_register_line" -lt "$session_anchor_close_line" \
   && "$session_anchor_close_line" -lt "$session_anchor_empty_line" \
   && "$session_anchor_empty_line" -lt "$session_unlink_line" \
   && "$session_unlink_line" -lt "$session_open_line" ]] \
  || fail 'restore FIFO sessions must register every startup resource before the next blocking lifecycle step'
normal_close_line=$(grep -nF 'close_psql_session() {' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
normal_close_input_line=$(awk -v start="$normal_close_line" \
  'NR > start && /close_psql_fd_if_open "\$session_input"/ { print NR; exit }' \
  "$restore_runner")
normal_forget_input_line=$(awk -v start="$normal_close_input_line" \
  'NR > start && /forget_psql_session_input_fd "\$label"/ { print NR; exit }' \
  "$restore_runner")
normal_drain_line=$(awk -v start="$normal_forget_input_line" \
  'NR > start && /drain_psql_output_fd "\$session_output"/ { print NR; exit }' \
  "$restore_runner")
normal_wait_line=$(awk -v start="$normal_drain_line" \
  'NR > start && /wait "\$session_pid"/ { print NR; exit }' "$restore_runner")
normal_forget_pid_line=$(awk -v start="$normal_wait_line" \
  'NR > start && /forget_psql_session_pid "\$label"/ { print NR; exit }' \
  "$restore_runner")
normal_close_output_line=$(awk -v start="$normal_forget_pid_line" \
  'NR > start && /close_psql_fd_if_open "\$session_output"/ { print NR; exit }' \
  "$restore_runner")
normal_forget_output_line=$(awk -v start="$normal_close_output_line" \
  'NR > start && /forget_psql_session_output_fd "\$label"/ { print NR; exit }' \
  "$restore_runner")
normal_clear_line=$(awk -v start="$normal_forget_output_line" \
  'NR > start && /clear_psql_session_registration "\$label"/ { print NR; exit }' \
  "$restore_runner")
[[ -n "$normal_close_line" && -n "$normal_close_input_line" \
   && -n "$normal_forget_input_line" && -n "$normal_drain_line" \
   && -n "$normal_wait_line" && -n "$normal_forget_pid_line" \
   && -n "$normal_close_output_line" && -n "$normal_forget_output_line" \
   && -n "$normal_clear_line" \
   && "$normal_close_line" -lt "$normal_close_input_line" \
   && "$normal_close_input_line" -lt "$normal_forget_input_line" \
   && "$normal_forget_input_line" -lt "$normal_drain_line" \
   && "$normal_drain_line" -lt "$normal_wait_line" \
   && "$normal_wait_line" -lt "$normal_forget_pid_line" \
   && "$normal_forget_pid_line" -lt "$normal_close_output_line" \
   && "$normal_close_output_line" -lt "$normal_forget_output_line" \
   && "$normal_forget_output_line" -lt "$normal_clear_line" ]] \
  || fail 'restore must close input, drain stdout, reap the child, then close output and clear exact registrations'
if grep -Fq 'cat "$grant_apply_sql" >&"$control_session_in"' "$restore_runner" \
   || grep -Fq 'cat "$capability_manifest_sql" >&"$control_session_in"' "$restore_runner" \
   || grep -Fq 'cat "$grant_apply_sql" >&"$target_coordinator_in"' "$restore_runner" \
   || grep -Fq 'cat "$capability_manifest_sql" >&"$target_coordinator_in"' "$restore_runner"; then
  fail 'restore must never stream replacement policy into the controller or target coordinator'
fi
[[ "$(grep -Fc 'psql_connection_arguments=(--dbname=postgres)' "$restore_runner")" == 1 ]] \
  || fail 'restore must have exactly one bounded maintenance-database control connection'
control_identity_line=$(grep -nF \
  '[[ "$control_database" == postgres && "$control_backend_pid" =~ ^[0-9]+$ ]]' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
target_discovery_line=$(grep -nF 'discover_target_coordinator_identity || return 1' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
maintenance_lock_line=$(grep -nF 'acquire_target_coordination_locks || return 1' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
primary_identity_line=$(grep -nF 'verify_primary_target_identity || return 1' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
policy_lock_line=$(grep -nF 'acquire_primary_policy_lock || return 1' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
current_preflight_line=$(grep -nE '^  preflight_current_database_recoverability$' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
[[ -n "$control_identity_line" && -n "$target_discovery_line" \
   && -n "$maintenance_lock_line" && -n "$primary_identity_line" \
   && -n "$policy_lock_line" && -n "$current_preflight_line" \
   && "$control_identity_line" -lt "$target_discovery_line" \
   && "$target_discovery_line" -lt "$maintenance_lock_line" \
   && "$maintenance_lock_line" -lt "$primary_identity_line" \
   && "$primary_identity_line" -lt "$policy_lock_line" \
   && "$policy_lock_line" -lt "$current_preflight_line" ]] \
  || fail 'restore authority setup must order controller, coordinator lock, primary policy and preflight exactly'
rollback_dump_line=$(grep -nF 'run_pg_client_without_parent_fds pg_dump' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
compensation_worker_line=$(grep -nF 'start_compensation_worker' "$restore_runner" \
  | tail -n 1 | cut -d: -f1)
fence_activation_line=$(grep -nF 'activate_target_database_fence' "$restore_runner" \
  | tail -n 1 | cut -d: -f1)
policy_unlock_line=$(grep -nF 'release_primary_policy_lock_after_fence' "$restore_runner" \
  | tail -n 1 | cut -d: -f1)
allow_connections_false_line=$(grep -nF 'set_target_database_connections false' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
exact_target_sessions_line=$(grep -nF \
  'if (( remaining_sessions != 0 || allowed_sessions != 3 )); then' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
hard_fence_state_line=$(grep -nF 'database_fence_active=true' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
replace_function_line=$(grep -nF 'replace_database_from_dump() {' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
xid_capture_line=$(awk -v start="$replace_function_line" \
  'NR > start && /pg_catalog\.pg_current_xact_id\(\)::text/ { print NR; exit }' \
  "$restore_runner")
xid_intent_line=$(grep -nF \
  'journal_append database-transaction-intent "$transaction_kind" "$label"' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
synchronous_commit_line=$(grep -nF 'SET LOCAL synchronous_commit TO on;' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
drop_schema_line=$(grep -nF \
  "EXECUTE format('DROP SCHEMA %I CASCADE', user_schema.nspname);" \
  "$restore_runner" | head -n 1 | cut -d: -f1)
[[ -n "$policy_lock_line" && -n "$rollback_dump_line" \
   && "$policy_lock_line" -lt "$rollback_dump_line" \
   && -n "$compensation_worker_line" \
   && -n "$fence_activation_line" \
   && "$rollback_dump_line" -lt "$compensation_worker_line" \
   && "$compensation_worker_line" -lt "$fence_activation_line" \
   && -n "$policy_unlock_line" \
   && "$fence_activation_line" -lt "$policy_unlock_line" ]] \
  || fail 'restore must hold policy through rollback capture, fence exact workers, then release it'
[[ -n "$allow_connections_false_line" && -n "$exact_target_sessions_line" \
   && -n "$hard_fence_state_line" \
   && "$allow_connections_false_line" -lt "$exact_target_sessions_line" \
   && "$exact_target_sessions_line" -lt "$hard_fence_state_line" ]] \
  || fail 'restore hard fence must disable new connections and prove exactly three target sessions before activation'
[[ -n "$replace_function_line" && -n "$xid_capture_line" \
   && -n "$xid_intent_line" && -n "$drop_schema_line" \
   && "$replace_function_line" -lt "$xid_capture_line" \
   && "$xid_capture_line" -lt "$xid_intent_line" \
   && "$xid_intent_line" -lt "$drop_schema_line" ]] \
  || fail 'restore must obtain and durably journal its xid8 before sending destructive SQL'
require_literal "$restore_runner" '"target-database=$target_database"' \
  'restore XID journal intent must bind the target database'
require_literal "$restore_runner" '"worker-backend-pid=$worker_backend_pid"' \
  'restore XID journal intent must bind the exact executor backend'
journal_block=$(shell_function_block "$restore_runner" journal_append)
[[ "$journal_block" == *'os.fsync(fd)'* \
   && "$journal_block" == *'while remaining:'* \
   && "$journal_block" == *'written = os.write(fd, remaining)'* \
   && "$journal_block" == *'if ! python3 - "$journal_file" "$@"'* \
   && "$journal_block" == *'fsync_path "$cutover_dir" || return 1'* ]] \
  || fail 'restore journal must propagate complete-write, file-fsync and directory-fsync failures'
[[ "$connection_fence_block" == *'control_session_command "$sql_file" "$output_file" || return 1'* \
   && "$connection_fence_block" == *'__NORTHSTAR_ALLOW_CONNECTIONS__'* \
   && "$connection_fence_block" == *'"$catalog_count" != 1'* \
   && "$connection_fence_block" == *'"$catalog_value" != "$expected"'* ]] \
  || fail 'restore connection fence must verify the exact pg_database catalog state'
[[ "$release_fence_block" == *'if ! set_target_database_connections true; then'* \
   && "$release_fence_block" == *'database_outcome_unknown=true'* ]] \
  || fail 'restore must remain fail-closed when the database connection fence cannot be released'
[[ -n "$post_grant_commit_line" && -n "$synchronous_commit_line" \
   && "$grant_apply_line" -lt "$synchronous_commit_line" \
   && "$synchronous_commit_line" -lt "$post_grant_commit_line" ]] \
  || fail 'restore must force a synchronous replacement commit after ACL convergence'
ready_wait_line=$(grep -nF \
  'psql_session_wait_token "$worker_out" "$ready_token" "$output_file"' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
active_transaction_line=$(grep -nF 'restore_transaction_active=true' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
normal_settle_line=$(grep -nF 'settle_active_restore_transaction || return 2' \
  "$restore_runner" | tail -n 1 | cut -d: -f1)
[[ -n "$active_transaction_line" && -n "$ready_wait_line" \
   && -n "$drop_schema_line" \
   && "$active_transaction_line" -lt "$ready_wait_line" \
   && "$ready_wait_line" -lt "$drop_schema_line" \
   && -n "$normal_settle_line" \
   && "$post_grant_commit_line" -lt "$normal_settle_line" ]] \
  || fail 'restore must require READY before destructive SQL and settle COMMIT before classifying pg_xact_status'
finish_restore_line=$(grep -nF 'finish_restore() {' "$restore_runner" \
  | head -n 1 | cut -d: -f1)
finish_signal_mask_line=$(awk -v start="$finish_restore_line" \
  "NR > start && /trap '' INT TERM/ { print NR; exit }" "$restore_runner")
finish_local_state_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /local status="\$1" compensation_ok=true fence_ok=true cleanup_ok=true/ { print NR; exit }' \
  "$restore_runner")
finish_reentry_guard_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /if \[\[ "\$cleanup_running" == true \]\]/ { print NR; exit }' \
  "$restore_runner")
finish_clear_exit_line=$(awk -v start="$finish_reentry_guard_line" \
  'NR > start && /trap - ERR EXIT/ { print NR; exit }' "$restore_runner")
[[ -n "$finish_restore_line" && -n "$finish_signal_mask_line" \
   && -n "$finish_local_state_line" \
   && -n "$finish_reentry_guard_line" && -n "$finish_clear_exit_line" \
   && "$finish_restore_line" -lt "$finish_signal_mask_line" \
   && "$finish_signal_mask_line" -lt "$finish_local_state_line" \
   && "$finish_local_state_line" -lt "$finish_reentry_guard_line" \
   && "$finish_reentry_guard_line" -lt "$finish_clear_exit_line" ]] \
  || fail 'restore cleanup must mask asynchronous termination before its re-entry guard clears EXIT'
finish_settle_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /settle_active_restore_transaction/ { print NR; exit }' "$restore_runner")
finish_generation_line=$(awk -v start="$finish_settle_line" \
  'NR > start && /incoming_restore_status/ { print NR; exit }' "$restore_runner")
[[ -n "$finish_settle_line" && -n "$finish_generation_line" \
   && "$finish_settle_line" -lt "$finish_generation_line" ]] \
  || fail 'restore cleanup must settle any active replacement transaction before trusting generation state'
finish_abort_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /abort_active_restore_worker_for_cleanup/ { print NR; exit }' "$restore_runner")
if [[ -n "$finish_abort_line" ]]; then
  fail 'restore cleanup must terminate an interrupted worker through the settle helper, not bypass its barrier state'
fi
require_literal "$restore_runner" \
  'if [[ "$cleanup_running" == true ]]; then' \
  'restore settle path does not distinguish interrupted cleanup'
require_literal "$restore_runner" \
  'abort_psql_session_for_cleanup "$active_restore_worker" "$output_file"' \
  'restore cleanup does not close the exact registered active worker before waiting'
settle_function_line=$(grep -nF 'settle_active_restore_transaction() {' \
  "$restore_runner" | head -n 1 | cut -d: -f1)
settle_cleanup_line=$(awk -v start="$settle_function_line" \
  'NR > start && /if \[\[ "\$cleanup_running" == true \]\]/ { print NR; exit }' \
  "$restore_runner")
settle_abort_line=$(awk -v start="$settle_cleanup_line" \
  'NR > start && /abort_active_restore_worker_for_cleanup/ { print NR; exit }' \
  "$restore_runner")
settle_barrier_line=$(awk -v start="$settle_abort_line" \
  'NR > start && /wait_for_restore_transaction_barrier/ { print NR; exit }' \
  "$restore_runner")
[[ -n "$settle_function_line" && -n "$settle_cleanup_line" \
   && -n "$settle_abort_line" && -n "$settle_barrier_line" \
   && "$settle_function_line" -lt "$settle_cleanup_line" \
   && "$settle_cleanup_line" -lt "$settle_abort_line" \
   && "$settle_abort_line" -lt "$settle_barrier_line" ]] \
  || fail 'interrupted restore cleanup must end the exact worker before waiting on its transaction barrier'
committed_finish_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /if \[\[ "\$restore_committed" == true \]\]/ { print NR; exit }' \
  "$restore_runner")
committed_settle_line=$(awk -v start="$committed_finish_line" \
  'NR > start && /settle_active_restore_transaction/ { print NR; exit }' "$restore_runner")
committed_generation_line=$(awk -v start="$committed_settle_line" \
  'NR > start && /incoming_restore_status/ { print NR; exit }' \
  "$restore_runner")
finish_release_line=$(awk -v start="$finish_restore_line" \
  'NR > start && /release_target_database_fence/ { print NR; exit }' "$restore_runner")
[[ -n "$committed_finish_line" && -n "$committed_settle_line" \
   && -n "$committed_generation_line" && -n "$finish_release_line" \
   && "$committed_finish_line" -lt "$committed_settle_line" \
   && "$committed_settle_line" -lt "$committed_generation_line" \
   && "$committed_generation_line" -lt "$finish_release_line" ]] \
  || fail 'committed restore cleanup must settle and verify the committed incoming generation before releasing the fence'
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

# Recovery and replay fixtures are architecture tests, not arbitrary database
# mutation scripts. Keep them pinned to the same closed-world authorities used
# by runtime so a future schema refactor cannot silently turn the tests into
# assertions over abandoned tables or ambiguous newest-row heuristics.
for legacy_probe_table in backup_probe restore_guard_probe untouched_probe \
  rollback_probe same_uuid_probe new_activation_probe signal_probe budget_probe; do
  if grep -Eq "CREATE[[:space:]]+TABLE[[:space:]]+${legacy_probe_table}([[:space:](]|$)" \
      "$disaster_fixture"; then
    fail "disaster recovery must not add test-only public table: $legacy_probe_table"
  fi
done
for canonical_probe_contract in \
  'seed_canonical_probe() {' \
  'INSERT INTO public.users' \
  'INSERT INTO public.vcards' \
  'apply_repository_migrations northstar_restore_target' \
  'reconcile_repository_grants northstar_restore_target'; do
  require_literal "$disaster_fixture" "$canonical_probe_contract" \
    "disaster recovery canonical probe contract is missing: $canonical_probe_contract"
done

if grep -Fq 'offline_message_admissions' "$message_pow_fixture"; then
  fail 'message PoW wire recovery must not inspect or mutate the legacy offline-only admission table'
fi
for personal_replay_contract in \
  'def wait_for_abuse_admission(' \
  'proof_challenge_id=' \
  'def ordering_barrier(' \
  'def recipient_ordering_barrier(' \
  'def wait_for_personal_delivery_projection(' \
  'def wait_for_personal_tombstone(' \
  'personal_message_admissions' \
  "identity_kind='local-origin'" \
  'actor_scope=' \
  'target_scope=' \
  'identity_value=' \
  "delivery_completed_at + INTERVAL '30 days'" \
  'sender_archive_id IS NULL' \
  'recipient_archive_id IS NULL' \
  'offline_message_id IS NULL' \
  's2s_outbox_id IS NULL' \
  'crash_admission_key' \
  'BEGIN; DELETE FROM personal_message_admissions ' \
  '; DELETE FROM offline_messages WHERE id=' \
  '; UPDATE abuse_message_admissions ' \
  "SET state='pending'" \
  "; COMMIT;"; do
  require_literal "$message_pow_fixture" "$personal_replay_contract" \
    "message PoW canonical replay contract is missing: $personal_replay_contract"
done
require_literal "$integration_fixture" 'def send_with_pow_proof(' \
  'XMPP wire tests must be able to replay the exact original PoW challenge and nonce'
for exact_wire_replay in \
  'alice.send_with_pow_proof(accepted, accepted_proof)' \
  'alice.send_with_pow_proof(remote, remote_proof)' \
  'alice.send_with_pow_proof(state["crash_stanza"], state["crash_proof"])' \
  'recipient_ordering_barrier(' \
  'WHERE stanza LIKE '; do
  require_literal "$message_pow_fixture" "$exact_wire_replay" \
    "message PoW exact wire/replay barrier is missing: $exact_wire_replay"
done
pow_crash_personal_line=$(grep -nF 'BEGIN; DELETE FROM personal_message_admissions ' \
  "$message_pow_fixture" | head -n 1 | cut -d: -f1)
pow_crash_offline_line=$(grep -nF '; DELETE FROM offline_messages WHERE id=' \
  "$message_pow_fixture" | head -n 1 | cut -d: -f1)
pow_crash_pending_line=$(grep -nF '; UPDATE abuse_message_admissions ' \
  "$message_pow_fixture" | head -n 1 | cut -d: -f1)
[[ -n "$pow_crash_personal_line" && -n "$pow_crash_offline_line" \
   && -n "$pow_crash_pending_line" \
   && "$pow_crash_personal_line" -lt "$pow_crash_offline_line" \
   && "$pow_crash_offline_line" -lt "$pow_crash_pending_line" ]] \
  || fail 'message PoW crash cut must remove personal authority before queue content, then reset the exact lease'
if grep -Fq "ORDER BY accepted_at DESC LIMIT 1" "$message_pow_fixture"; then
  fail 'message PoW recovery must identify the exact admission instead of selecting a global newest row'
fi
if grep -Fq 'except (TimeoutError, OSError)' "$message_pow_fixture"; then
  fail 'message PoW replay observation must not mistake a reset connection for an empty delivery window'
fi
if grep -Fq 'time.sleep(0.25)' "$message_pow_fixture"; then
  fail 'message PoW persistence synchronization must use exact protocol/database state instead of fixed sleeps'
fi
if grep -Fq 'no_matching_frame' "$message_pow_fixture"; then
  fail 'message PoW duplicate suppression must use an ordered recipient barrier instead of a timed absence window'
fi

muc_pause_line=$(grep -nF 'install_muc_authorization_test_pause("admin_affiliation")' \
  "$muc_source" | head -n 1 | cut -d: -f1)
muc_revoke_line=$(awk -v start="$muc_pause_line" \
  'NR > start && /set_muc_affiliation\(&pool, room_id, "carol", "none"\)/ { print NR; exit }' \
  "$muc_source")
muc_applied_line=$(awk -v start="$muc_revoke_line" \
  'NR > start && /MucAffiliationOutcome::Applied/ { print NR; exit }' "$muc_source")
muc_resume_line=$(awk -v start="$muc_applied_line" \
  'NR > start && /resume\.notify_one\(\)/ { print NR; exit }' "$muc_source")
[[ -n "$muc_pause_line" && -n "$muc_revoke_line" && -n "$muc_applied_line" \
   && -n "$muc_resume_line" && "$muc_pause_line" -lt "$muc_revoke_line" \
   && "$muc_revoke_line" -lt "$muc_applied_line" \
   && "$muc_applied_line" -lt "$muc_resume_line" ]] \
  || fail 'MUC affiliation race must prove a real applied owner-to-none revocation before resuming the read'
require_literal "$muc_protocol_source" \
  'members_can_retrieve_omemo_recipient_lists_in_private_non_anonymous_rooms' \
  'MUC member affiliation-list exception must retain a direct OMEMO policy regression test'
for muc_repository_policy in \
  'set_muc_affiliation(&pool, room_id, "carol", "member")' \
  'for requested in ["owner", "admin", "member"]' \
  '"outcast"'; do
  require_literal "$muc_source" "$muc_repository_policy" \
    "MUC PostgreSQL fixture must exercise the real member affiliation-list policy: $muc_repository_policy"
done

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
