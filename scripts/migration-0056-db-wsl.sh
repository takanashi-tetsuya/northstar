#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="${XMPP_TEST_SCHEMA:-northstar_m0056_$random_suffix}"

if [[ "$test_database" != "xmpp_test" ]]; then
  echo "refusing to run migration 0056 tests outside the disposable xmpp_test database" >&2
  exit 2
fi
if [[ ! "$test_schema" =~ ^northstar_m0056_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe or non-random XMPP_TEST_SCHEMA: $test_schema" >&2
  exit 2
fi

database_args=(--host 127.0.0.1 --username xmpp_test --dbname xmpp_test)
created=0

psql_test() {
  PGPASSWORD=xmpp-test-password PGOPTIONS="-c search_path=$test_schema" psql \
    "${database_args[@]}" \
    --set ON_ERROR_STOP=1 "$@"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$created" == 1 ]]; then
    PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --set ON_ERROR_STOP=1 \
      --command "DROP SCHEMA IF EXISTS \"$test_schema\" CASCADE" >/dev/null || status=1
    remains="$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
      --tuples-only --no-align \
      --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')" \
      2>/dev/null || printf unknown)"
    if [[ "$remains" != "f" ]]; then
      echo "isolated migration 0056 schema was not removed: $test_schema (exists=$remains)" >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$(PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --tuples-only --no-align \
  --command "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
PGPASSWORD=xmpp-test-password psql "${database_args[@]}" \
  --set ON_ERROR_STOP=1 \
  --command "CREATE SCHEMA \"$test_schema\"" >/dev/null
created=1

for migration in "$project_dir"/migrations/*.sql; do
  filename="${migration##*/}"
  version="${filename%%_*}"
  if ((10#$version > 55)); then
    continue
  fi
  psql_test --file "$migration" >/dev/null
done

psql_test >/dev/null <<'SQL'
INSERT INTO users(id,username,password_hash)
VALUES('00000000-0000-0000-0000-000000000001','migration-owner','test-only');
INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
VALUES('00000000-0000-0000-0000-000000000002',
       '00000000-0000-0000-0000-000000000001','peer@example.test','peer@example.test/r',
       '<message xmlns="jabber:client"/>',FALSE),
      ('00000000-0000-0000-0000-000000000006',
       '00000000-0000-0000-0000-000000000001','upgrade@example.test','upgrade@example.test/r',
       '<message xmlns="jabber:client"/>',FALSE);
-- payload_value is intentional here: this schema stops at migration 0055.
-- The surviving row below is later upgraded through 0104 in this same
-- isolated schema to prove that the historical plaintext is destroyed.
INSERT INTO personal_message_admissions
  (id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,
   identity_digest,payload_value,payload_digest,sender_archive_id)
VALUES
  ('00000000-0000-0000-0000-000000000003','local-origin','migration-owner@example.test',
   'migration-owner@example.test','peer@example.test','valid',repeat(E'\\001',32)::bytea,
   '<message/>',repeat(E'\\002',32)::bytea,'00000000-0000-0000-0000-000000000002'),
  ('00000000-0000-0000-0000-000000000004','local-origin','migration-owner@example.test',
   'migration-owner@example.test','peer@example.test','orphan',repeat(E'\\003',32)::bytea,
   '<message/>',repeat(E'\\004',32)::bytea,'00000000-0000-0000-0000-000000000099'),
  ('00000000-0000-0000-0000-000000000005','local-origin','migration-owner@example.test',
   'migration-owner@example.test','upgrade@example.test','upgrade-through-0104',
   repeat(E'\\005',32)::bytea,
   '<message><body>M0056-LEGACY-CONTENT-MARKER</body></message>',
   repeat(E'\\006',32)::bytea,'00000000-0000-0000-0000-000000000006');
SQL

psql_test --file "$project_dir/migrations/0056_personal_message_admission_ownership.sql" >/dev/null

remaining="$(psql_test --tuples-only --no-align --command \
  "SELECT count(*) FROM personal_message_admissions")"
[[ "$remaining" == "2" ]] || { echo "0056 did not remove exactly the orphan" >&2; exit 1; }

psql_test --command \
  "DELETE FROM message_archive WHERE id='00000000-0000-0000-0000-000000000002'" >/dev/null
remaining="$(psql_test --tuples-only --no-align --command \
  "SELECT count(*) FROM personal_message_admissions")"
[[ "$remaining" == "1" ]] || { echo "0056 archive cascade did not remove admission" >&2; exit 1; }

# Continue the same historical row through the current content-identity
# migration. This is intentionally not an application runtime migration: it
# is an isolated upgrade fixture that proves 0104 preserves only the legacy
# digest while irreversibly dropping payload_value.
for migration in "$project_dir"/migrations/*.sql; do
  filename="${migration##*/}"
  version="${filename%%_*}"
  if ((10#$version <= 56 || 10#$version > 104)); then
    continue
  fi
  psql_test --file "$migration" >/dev/null
done

plaintext_column="$(psql_test --tuples-only --no-align --command \
  "SELECT count(*) FROM information_schema.columns
    WHERE table_schema=current_schema()
      AND table_name='personal_message_admissions'
      AND column_name='payload_value'")"
[[ "$plaintext_column" == "0" ]] || {
  echo "0104 did not remove personal_message_admissions.payload_value" >&2
  exit 1
}

legacy_shape="$(psql_test --tuples-only --no-align --command \
  "SELECT CASE WHEN payload_key_id IS NULL THEN '1' ELSE '0' END || '|' ||
          CASE WHEN payload_mac IS NULL THEN '1' ELSE '0' END || '|' ||
          encode(payload_digest,'hex')
     FROM personal_message_admissions
    WHERE id='00000000-0000-0000-0000-000000000005'")"
expected_legacy_digest="$(printf '06%.0s' {1..32})"
[[ "$legacy_shape" == "1|1|$expected_legacy_digest" ]] || {
  echo "0104 did not preserve the irreversible legacy digest shape: $legacy_shape" >&2
  exit 1
}

if psql_test --command \
  "UPDATE personal_message_admissions
      SET payload_digest=NULL
    WHERE id='00000000-0000-0000-0000-000000000005'" >/dev/null 2>&1; then
  echo "0104 accepted an all-empty personal-message evidence shape" >&2
  exit 1
fi

psql_test --command \
  "DELETE FROM message_archive
    WHERE id='00000000-0000-0000-0000-000000000006'" >/dev/null
terminal_identity="$(psql_test --tuples-only --no-align --command \
  "SELECT CASE WHEN sender_archive_id IS NULL THEN '1' ELSE '0' END || '|' ||
          CASE WHEN delivery_completed_at IS NOT NULL THEN '1' ELSE '0' END
     FROM personal_message_admissions
    WHERE id='00000000-0000-0000-0000-000000000005'")"
[[ "$terminal_identity" == "1|1" ]] || {
  echo "current projection finalizer did not preserve the upgraded replay identity: $terminal_identity" >&2
  exit 1
}

echo "migration 0056 dirty-data cleanup/archive cascade and 0104 plaintext-erasure upgrade: ok"
