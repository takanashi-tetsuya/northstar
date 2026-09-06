#!/usr/bin/env bash
set -euo pipefail
umask 077

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

test_database="${XMPP_TEST_DATABASE:-xmpp_test}"
if [[ "$test_database" != "xmpp_test" ]]; then
  echo "migration upgrade validation is restricted to the dedicated xmpp_test database" >&2
  exit 2
fi

for required in cargo psql sha256sum sha384sum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "migration upgrade validation requires $required" >&2
    exit 2
  fi
done

bash scripts/check-migration-versions.sh
baseline_manifest="scripts/fixtures/migrations-0001-0013.sha256"
if [[ ! -f "$baseline_manifest" ]]; then
  echo "missing immutable migration baseline: $baseline_manifest" >&2
  exit 2
fi

manifest_paths="$(awk 'NF == 2 { print $2 }' "$baseline_manifest" | sort)"
baseline_paths="$(find migrations -maxdepth 1 -type f -name '*.sql' -print \
  | awk -F/ '{ name=$NF; version=substr(name,1,4)+0; if (version >= 1 && version <= 13) print }' \
  | sort)"
if [[ "$manifest_paths" != "$baseline_paths" ]]; then
  echo "the immutable 0001-0013 manifest does not name exactly the historical baseline" >&2
  diff -u <(printf '%s\n' "$baseline_paths") <(printf '%s\n' "$manifest_paths") >&2 || true
  exit 1
fi
if [[ "$(printf '%s\n' "$manifest_paths" | sed '/^$/d' | wc -l | tr -d ' ')" != "13" ]]; then
  echo "the immutable migration baseline must contain exactly 13 files" >&2
  exit 1
fi
random_suffix="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
test_schema="northstar_mupgrade_$random_suffix"
pre_fix_schema="northstar_m0132_$random_suffix"
if [[ ! "$test_schema" =~ ^northstar_mupgrade_[a-f0-9]{32}$ ]] ||
   (( ${#test_schema} > 63 )); then
  echo "refusing unsafe migration upgrade schema name: $test_schema" >&2
  exit 2
fi
if [[ ! "$pre_fix_schema" =~ ^northstar_m0132_[a-f0-9]{32}$ ]] ||
   (( ${#pre_fix_schema} > 63 )); then
  echo "refusing unsafe migration 0132 schema name: $pre_fix_schema" >&2
  exit 2
fi

database_args=(
  --no-psqlrc
  --host 127.0.0.1
  --port 5432
  --username xmpp_test
  --dbname xmpp_test
  --set ON_ERROR_STOP=1
)
created=0
pre_fix_created=0

psql_admin() {
  PGPASSWORD=xmpp-test-password PGOPTIONS="-c client_min_messages=warning" \
    psql "${database_args[@]}" "$@"
}

psql_schema() {
  PGPASSWORD=xmpp-test-password \
    PGOPTIONS="-c search_path=$test_schema -c client_min_messages=warning" \
    psql "${database_args[@]}" "$@"
}

drop_test_schema() {
  if [[ ! "$test_schema" =~ ^northstar_mupgrade_[a-f0-9]{32}$ ]]; then
    echo "refusing to clean an unexpected schema name: $test_schema" >&2
    return 1
  fi
  psql_admin --command "DROP SCHEMA \"$test_schema\" CASCADE" >/dev/null
  local remains
  remains="$(psql_admin --tuples-only --no-align --command \
    "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")"
  if [[ "$remains" != "f" ]]; then
    echo "isolated migration schema was not removed: $test_schema (exists=$remains)" >&2
    return 1
  fi
}

drop_pre_fix_schema() {
  if [[ ! "$pre_fix_schema" =~ ^northstar_m0132_[a-f0-9]{32}$ ]]; then
    echo "refusing to clean an unexpected migration 0132 schema name: $pre_fix_schema" >&2
    return 1
  fi
  psql_admin --command "DROP SCHEMA \"$pre_fix_schema\" CASCADE" >/dev/null
  local remains
  remains="$(psql_admin --tuples-only --no-align --command \
    "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$pre_fix_schema')")"
  if [[ "$remains" != "f" ]]; then
    echo "isolated migration 0132 schema was not removed: $pre_fix_schema (exists=$remains)" >&2
    return 1
  fi
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$pre_fix_created" == "1" ]]; then
    if ! drop_pre_fix_schema; then
      status=1
    fi
  fi
  if [[ "$created" == "1" ]]; then
    if ! drop_test_schema; then
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

server_identity="$(psql_admin --tuples-only --no-align --command \
  "SELECT current_database() || '|' || current_user")"
if [[ "$server_identity" != "xmpp_test|xmpp_test" ]]; then
  echo "refusing unexpected PostgreSQL target: $server_identity" >&2
  exit 2
fi
if [[ "$(psql_admin --tuples-only --no-align --command \
  "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$test_schema')")" == "t" ]]; then
  echo "refusing to reuse existing PostgreSQL schema: $test_schema" >&2
  exit 2
fi
psql_admin --command "CREATE SCHEMA \"$test_schema\" AUTHORIZATION xmpp_test" >/dev/null
created=1
if [[ "$(psql_schema --tuples-only --no-align --command 'SELECT current_schema()')" != "$test_schema" ]]; then
  echo "PostgreSQL did not select the isolated migration schema" >&2
  exit 1
fi

psql_schema >/dev/null <<'SQL'
CREATE TABLE _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
SQL

while IFS= read -r migration; do
  [[ -n "$migration" ]] || continue
  filename="${migration##*/}"
  version_text="${filename%%_*}"
  version="$((10#$version_text))"
  stem="${filename%.sql}"
  description="${stem#*_}"
  description="${description//_/ }"
  checksum="$(sha384sum "$migration" | awk '{print $1}')"
  psql_schema --single-transaction --file "$migration" >/dev/null
  psql_schema --command \
    "INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES($version,'$description',TRUE,decode('$checksum','hex'),0)" \
    >/dev/null
done <<<"$manifest_paths"

baseline_state="$(psql_schema --tuples-only --no-align --command \
  "SELECT COUNT(*) || '|' || MIN(version) || '|' || MAX(version) || '|' || bool_and(success) FROM _sqlx_migrations")"
if [[ "$baseline_state" != "13|1|13|true" ]]; then
  echo "failed to prepare the exact SQLx 0013 baseline: $baseline_state" >&2
  exit 1
fi

psql_schema >/dev/null <<'SQL'
INSERT INTO users(id,username,password_hash,display_name,is_admin)
VALUES
  ('00000000-0000-0000-0000-000000000001','alice','legacy-hash-a','Alice Legacy',TRUE),
  ('00000000-0000-0000-0000-000000000002','bob','legacy-hash-b','Bob Legacy',FALSE);

INSERT INTO api_sessions(id,user_id,token_hash,expires_at)
VALUES('00000000-0000-0000-0000-000000000101',
       '00000000-0000-0000-0000-000000000001',decode(repeat('11',32),'hex'),'2099-01-01T00:00:00Z');

INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,ask,groups)
VALUES('00000000-0000-0000-0000-000000000001','bob@example.test','Bob','both',NULL,'["Friends"]');

INSERT INTO pending_presence_subscriptions(requester_id,recipient_id)
VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002');
INSERT INTO blocked_jids(owner_id,blocked_jid)
VALUES('00000000-0000-0000-0000-000000000001','blocked@example.test');

INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted)
VALUES('00000000-0000-0000-0000-000000000201',
       '00000000-0000-0000-0000-000000000002','alice@example.test/laptop',
       '<message xmlns="jabber:client"><body>legacy offline</body></message>',FALSE);
INSERT INTO message_archive(id,owner_id,peer_jid,stanza,encrypted,stanza_id)
VALUES('00000000-0000-0000-0000-000000000301',
       '00000000-0000-0000-0000-000000000001','bob@example.test',
       '<message xmlns="jabber:client"><body>legacy archive</body></message>',FALSE,'legacy-origin-1');

INSERT INTO pep_nodes(owner_id,node,access_model,max_items)
VALUES('00000000-0000-0000-0000-000000000001','urn:example:legacy','presence',10);
INSERT INTO pep_items(owner_id,node,item_id,payload)
VALUES('00000000-0000-0000-0000-000000000001','urn:example:legacy','legacy-item',
       '<entry xmlns="urn:example:legacy">preserve me</entry>');

INSERT INTO muc_rooms(id,localpart,title,owner_id,persistent,members_only)
VALUES('00000000-0000-0000-0000-000000000401','legacy-room','Legacy Room',
       '00000000-0000-0000-0000-000000000001',TRUE,TRUE);
INSERT INTO muc_affiliations(room_id,user_id,affiliation)
VALUES('00000000-0000-0000-0000-000000000401',
       '00000000-0000-0000-0000-000000000001','owner');
INSERT INTO muc_messages(id,room_id,sender_jid,nick,stanza,encrypted)
VALUES('00000000-0000-0000-0000-000000000402',
       '00000000-0000-0000-0000-000000000401','alice@example.test/laptop','Alice',
       '<message xmlns="jabber:client" type="groupchat"><body>legacy room</body></message>',FALSE);

INSERT INTO upload_slots(id,user_id,filename,content_type,size,token_hash,expires_at)
VALUES('00000000-0000-0000-0000-000000000501',
       '00000000-0000-0000-0000-000000000001','legacy.txt','text/plain',12,
       decode(repeat('22',32),'hex'),'2099-01-01T00:00:00Z');
INSERT INTO vcards(user_id,payload)
VALUES('00000000-0000-0000-0000-000000000001',
       '<vCard xmlns="vcard-temp"><FN>Alice Legacy</FN></vCard>');
INSERT INTO private_xml(user_id,element_name,element_ns,xml_data)
VALUES('00000000-0000-0000-0000-000000000001','settings','urn:example:settings',
       '<settings xmlns="urn:example:settings"><value>legacy</value></settings>');

INSERT INTO push_subscriptions(user_id,service_jid,node,options)
VALUES('00000000-0000-0000-0000-000000000001','push.example.test','legacy-node','<x/>');
INSERT INTO federated_presence_pending(recipient_id,from_jid)
VALUES('00000000-0000-0000-0000-000000000002','remote@remote.example.test');

INSERT INTO invitation_tokens(id,token_hash,label,created_by,max_uses,use_count,expires_at)
VALUES('00000000-0000-0000-0000-000000000601',decode(repeat('33',32),'hex'),'legacy invite',
       '00000000-0000-0000-0000-000000000001',5,1,'2099-01-01T00:00:00Z');
INSERT INTO abuse_reports(id,reporter_id,reported_jid,category,description,status)
VALUES('00000000-0000-0000-0000-000000000701',
       '00000000-0000-0000-0000-000000000001','spammer@example.test','spam','legacy report','submitted');
INSERT INTO abuse_report_evidence(id,report_id,client_message_id,sender_jid,sent_at,body_text,encrypted,position)
VALUES('00000000-0000-0000-0000-000000000702',
       '00000000-0000-0000-0000-000000000701','legacy-message','spammer@example.test',
       '2026-01-01T00:00:00Z','legacy evidence',TRUE,0);
INSERT INTO abuse_appeals(id,report_id,appellant_id,reason)
VALUES('00000000-0000-0000-0000-000000000703',
       '00000000-0000-0000-0000-000000000701',
       '00000000-0000-0000-0000-000000000002','legacy appeal reason with sufficient detail');

INSERT INTO audit_log(actor_id,action,target,details,ip_address)
VALUES('00000000-0000-0000-0000-000000000001','legacy.migration.fixture','legacy-target',
       '{"preserve":true}','127.0.0.1');
SQL

snapshot_baseline_rows() {
  psql_schema --tuples-only --no-align <<'SQL'
SELECT 'users|' || id || '|' || username || '|' || password_hash || '|' || COALESCE(display_name,'') || '|' || is_admin || '|' || is_disabled FROM users ORDER BY id;
SELECT 'roster|' || owner_id || '|' || contact_jid || '|' || subscription || '|' || groups::text FROM roster_items ORDER BY owner_id,contact_jid;
SELECT 'offline|' || id || '|' || recipient_id || '|' || sender_jid || '|' || stanza || '|' || encrypted FROM offline_messages ORDER BY id;
SELECT 'archive|' || id || '|' || owner_id || '|' || peer_jid || '|' || stanza || '|' || encrypted || '|' || COALESCE(stanza_id,'') FROM message_archive ORDER BY id;
SELECT 'pep|' || owner_id || '|' || node || '|' || item_id || '|' || payload FROM pep_items WHERE node='urn:example:legacy' ORDER BY owner_id,node,item_id;
SELECT 'room|' || id || '|' || localpart || '|' || title || '|' || owner_id || '|' || persistent || '|' || members_only FROM muc_rooms ORDER BY id;
SELECT 'room-message|' || id || '|' || room_id || '|' || sender_jid || '|' || nick || '|' || stanza || '|' || encrypted FROM muc_messages ORDER BY id;
SELECT 'upload|' || id || '|' || user_id || '|' || filename || '|' || content_type || '|' || size || '|' || encode(token_hash,'hex') || '|' || uploaded FROM upload_slots ORDER BY id;
SELECT 'vcard|' || user_id || '|' || payload FROM vcards ORDER BY user_id;
SELECT 'private|' || user_id || '|' || element_name || '|' || element_ns || '|' || xml_data FROM private_xml ORDER BY user_id,element_name,element_ns;
SELECT 'push|' || user_id || '|' || service_jid || '|' || node || '|' || COALESCE(options,'') FROM push_subscriptions ORDER BY user_id,service_jid,node;
SELECT 'report|' || id || '|' || reporter_id || '|' || reported_jid || '|' || category || '|' || description || '|' || status FROM abuse_reports ORDER BY id;
SELECT 'evidence|' || id || '|' || report_id || '|' || COALESCE(client_message_id,'') || '|' || sender_jid || '|' || body_text || '|' || encrypted || '|' || position FROM abuse_report_evidence ORDER BY id;
SELECT 'invite|' || id || '|' || encode(token_hash,'hex') || '|' || label || '|' || max_uses || '|' || use_count FROM invitation_tokens ORDER BY id;
SQL
}

before_fingerprint="$(snapshot_baseline_rows | sha256sum | awk '{print $1}')"

if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" != "true" ]]; then
  export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export RUSTUP_HOME="$project_dir/.rustup-linux"
  export CARGO_HOME="$project_dir/.cargo-local"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$project_dir/target-wsl}"
fi
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema"
test_name="db::migration_upgrade_test::baseline_0013_upgrades_through_the_real_domain_migrator"

run_migrator() {
  local requested_test_name="$1"
  local output
  if ! output="$(cargo test --locked --offline "$requested_test_name" -- --ignored --exact --nocapture 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  if ! grep -Eq 'test result: ok\. 1 passed; 0 failed' <<<"$output"; then
    printf '%s\n' "$output" >&2
    echo "expected exactly one migration upgrade test to run" >&2
    return 1
  fi
}

run_migrator "$test_name"

after_fingerprint="$(snapshot_baseline_rows | sha256sum | awk '{print $1}')"
if [[ "$after_fingerprint" != "$before_fingerprint" ]]; then
  echo "representative 0013 data changed while upgrading to the current schema" >&2
  exit 1
fi

migration_files="$(find migrations -maxdepth 1 -type f -name '*.sql' -print | sort)"
expected_count="$(printf '%s\n' "$migration_files" | sed '/^$/d' | wc -l | tr -d ' ')"
expected_latest="$(printf '%s\n' "$migration_files" | sed 's#^.*/##;s#_.*##' | sed 's/^0*//;s/^$/0/' | sort -n | tail -n1)"
database_state="$(psql_schema --tuples-only --no-align --command \
  "SELECT COUNT(*) || '|' || MIN(version) || '|' || MAX(version) || '|' || bool_and(success) FROM _sqlx_migrations")"
if [[ "$database_state" != "$expected_count|1|$expected_latest|true" ]]; then
  echo "unexpected final SQLx migration state: $database_state (expected $expected_count|1|$expected_latest|true)" >&2
  exit 1
fi
if [[ "$(psql_schema --tuples-only --no-align --command \
  'SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=21)')" != "f" ]]; then
  echo "reserved migration version 0021 was unexpectedly recorded" >&2
  exit 1
fi

while IFS= read -r migration; do
  [[ -n "$migration" ]] || continue
  filename="${migration##*/}"
  version_text="${filename%%_*}"
  version="$((10#$version_text))"
  expected_checksum="$(sha384sum "$migration" | awk '{print $1}')"
  stored_checksum="$(psql_schema --tuples-only --no-align --command \
    "SELECT encode(checksum,'hex') FROM _sqlx_migrations WHERE version=$version")"
  if [[ "$stored_checksum" != "$expected_checksum" ]]; then
    echo "SQLx checksum mismatch for $migration" >&2
    exit 1
  fi
done <<<"$migration_files"

# Exercise the exact 0131 -> 0132 recovery boundary in a second, initially
# empty schema. The Rust fixture first installs the real chain through 0131,
# proves the b588 0132 body fails without a ledger row, then applies and
# repeats the corrected source. It also verifies that a deliberately injected
# pre-fix checksum is rejected rather than silently rewritten.
if [[ "$(psql_admin --tuples-only --no-align --command \
  "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='$pre_fix_schema')")" == "t" ]]; then
  echo "refusing to reuse existing migration 0132 schema: $pre_fix_schema" >&2
  exit 2
fi
psql_admin --command "CREATE SCHEMA \"$pre_fix_schema\" AUTHORIZATION xmpp_test" >/dev/null
pre_fix_created=1
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$pre_fix_schema"
run_migrator "db::migration_upgrade_test::migration_0132_pre_fix_failure_leaves_no_ledger_row_and_current_checksum_is_enforced"
drop_pre_fix_schema
pre_fix_created=0
export TEST_DATABASE_URL="postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test?options=-csearch_path%3D$test_schema"

version_one_checksum="$(sha384sum migrations/0001_initial.sql | awk '{print $1}')"
psql_schema --command \
  "UPDATE _sqlx_migrations SET checksum=set_byte(checksum,0,(get_byte(checksum,0)+1)%256) WHERE version=1" \
  >/dev/null
set +e
checksum_failure_output="$(cargo test --locked --offline "$test_name" -- --ignored --exact --nocapture 2>&1)"
checksum_failure_status=$?
set -e
if [[ "$checksum_failure_status" == "0" ]]; then
  echo "SQLx unexpectedly accepted a modified historical migration checksum" >&2
  exit 1
fi
if ! grep -Fq 'migration 1 was previously applied but has been modified' <<<"$checksum_failure_output"; then
  printf '%s\n' "$checksum_failure_output" >&2
  echo "migration failed for an unexpected reason after checksum tampering" >&2
  exit 1
fi
psql_schema --command \
  "UPDATE _sqlx_migrations SET checksum=decode('$version_one_checksum','hex') WHERE version=1" \
  >/dev/null

# A clean repeat validates both checksum recovery and migration idempotence.
run_migrator "$test_name"
final_fingerprint="$(snapshot_baseline_rows | sha256sum | awk '{print $1}')"
if [[ "$final_fingerprint" != "$before_fingerprint" ]]; then
  echo "representative baseline data changed after an idempotent migration rerun" >&2
  exit 1
fi

drop_test_schema
created=0
echo "migration upgrade validation passed: immutable 0001-0013 baseline -> current version $expected_latest; 0131 -> 0132 recovery, SQLx checksum rejection, representative data, idempotence and exact cleanup verified"
