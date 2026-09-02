#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
backup_dir=""
database_url_file="${DATABASE_URL_FILE:-}"
upload_dir="${UPLOAD_DIR:-$project_dir/data/uploads}"
rollback_dir="${ROLLBACK_DIR:-}"
plaintext_staging_root="${RESTORE_PLAINTEXT_STAGING_DIR:-${TMPDIR:-/tmp}}"
confirmation=""
public_key_file="${BACKUP_VERIFY_KEY_FILE:-}"
require_signature="${BACKUP_REQUIRE_SIGNATURE:-false}"
age_identity_file="${BACKUP_AGE_IDENTITY_FILE:-}"
rollback_state_file="${BACKUP_ROLLBACK_STATE_FILE:-}"
allow_rollback="${BACKUP_ALLOW_ROLLBACK:-false}"
allow_generation_change="${BACKUP_ALLOW_GENERATION_CHANGE:-false}"
security_policy="${BACKUP_SECURITY_POLICY:-production}"
max_upload_object_bytes="${RESTORE_MAX_UPLOAD_OBJECT_BYTES:-1073741824}"
max_upload_total_bytes="${RESTORE_MAX_UPLOAD_TOTAL_BYTES:-68719476736}"
reserve_free_bytes="${RESTORE_RESERVE_FREE_BYTES:-1073741824}"
maintenance_lock_key=735559096281326101
grant_boundary_sql="$project_dir/deploy/postgres-init/lib/verify-northstar-grant-boundary.sql"
grant_apply_sql="$project_dir/deploy/postgres-init/lib/apply-northstar-grants.sql"
capability_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-capability-manifest.sql"
migration_ledger_manifest_sql="$project_dir/deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql"
readonly database_migrator_role='northstar_migrator'
readonly database_runtime_role='northstar_runtime'
readonly database_command_role='northstar_commands'
readonly database_backup_role='northstar_backup'

usage() {
  cat >&2 <<EOF
usage: $0 BACKUP_DIRECTORY --confirm-restore NORTHSTAR-RESTORE --rollback-dir DIR [OPTIONS]

Restore only after signature, ciphertext/plaintext digests, archive structure,
resource budgets and the optional monotonic rollback policy have all passed.

Options:
  --database-url-file FILE       PostgreSQL URL secret file
  --upload-dir DIR               Strict upload-object target
  --rollback-dir DIR             Dedicated rollback-retention root
  --plaintext-staging-dir DIR    Private scratch (prefer tmpfs)
  --public-key-file FILE         Trusted OpenSSL Ed25519 public key
  --require-signature            Reject unsigned and legacy backups
  --age-identity-file FILE       age private identity (file only)
  --rollback-state-file FILE     Persistent trusted restore floor
  --allow-rollback               Deliberately restore an equal/older sequence
  --allow-generation-change      Deliberately trust a new generation
  --max-upload-object-bytes N    Maximum expanded bytes for one object
  --max-upload-total-bytes N     Maximum expanded bytes for all objects
  --reserve-free-bytes N         Free-space reserve on every working filesystem
  --development-insecure-legacy  Explicitly permit legacy/unsigned development restore
EOF
}

[[ $# -gt 0 ]] || { usage; exit 2; }
if [[ $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
  usage
  exit 0
fi
backup_dir="$1"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --confirm-restore) confirmation="${2:-}"; shift 2 ;;
    --database-url-file) database_url_file="${2:?missing database URL file}"; shift 2 ;;
    --upload-dir) upload_dir="${2:?missing upload directory}"; shift 2 ;;
    --rollback-dir) rollback_dir="${2:?missing rollback directory}"; shift 2 ;;
    --plaintext-staging-dir) plaintext_staging_root="${2:?missing staging directory}"; shift 2 ;;
    --public-key-file) public_key_file="${2:?missing public key file}"; shift 2 ;;
    --require-signature) require_signature=true; shift ;;
    --age-identity-file) age_identity_file="${2:?missing age identity file}"; shift 2 ;;
    --rollback-state-file) rollback_state_file="${2:?missing rollback state file}"; shift 2 ;;
    --allow-rollback) allow_rollback=true; shift ;;
    --allow-generation-change) allow_generation_change=true; shift ;;
    --max-upload-object-bytes) max_upload_object_bytes="${2:?missing object-byte limit}"; shift 2 ;;
    --max-upload-total-bytes) max_upload_total_bytes="${2:?missing total-byte limit}"; shift 2 ;;
    --reserve-free-bytes) reserve_free_bytes="${2:?missing free-space reserve}"; shift 2 ;;
    --development-insecure-legacy) security_policy=development-legacy; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

case "$security_policy" in
  production)
    require_signature=true
    allow_legacy=false
    ;;
  development-legacy)
    allow_legacy=true
    printf '%s\n' \
      'WARNING: development-legacy restore policy accepts backups that are unsuitable for production.' >&2
    ;;
  *)
    echo "BACKUP_SECURITY_POLICY must be production or development-legacy" >&2
    exit 2
    ;;
esac

[[ "$confirmation" == "NORTHSTAR-RESTORE" ]] \
  || { echo "restore refused: explicit confirmation phrase is required" >&2; exit 2; }
[[ -n "$rollback_dir" ]] \
  || { echo "restore refused: a dedicated --rollback-dir is required" >&2; exit 2; }

parse_bool() {
  local name="$1" value="${2,,}"
  case "$value" in
    1|true|yes) printf '%s' true ;;
    0|false|no) printf '%s' false ;;
    *) echo "$name must be true or false" >&2; return 2 ;;
  esac
}

require_signature="$(parse_bool BACKUP_REQUIRE_SIGNATURE "$require_signature")"
allow_rollback="$(parse_bool BACKUP_ALLOW_ROLLBACK "$allow_rollback")"
allow_generation_change="$(parse_bool BACKUP_ALLOW_GENERATION_CHANGE "$allow_generation_change")"

# Fail before database access, decryption, or plaintext materialization when a
# production trust capability is absent.
if [[ "$security_policy" == production ]]; then
  command -v grep >/dev/null \
    || { echo "production restore requires grep" >&2; exit 1; }
  [[ -n "$database_url_file" ]] \
    || { echo "production restore requires --database-url-file" >&2; exit 2; }
  [[ -f "$database_url_file" && ! -L "$database_url_file" && -r "$database_url_file" ]] \
    || { echo "production restore database URL must be a readable regular non-symlink file" >&2; exit 2; }
  [[ -n "$public_key_file" && -f "$public_key_file" && ! -L "$public_key_file" && -r "$public_key_file" ]] \
    || { echo "production restore requires a readable Ed25519 public key file" >&2; exit 2; }
  command -v openssl >/dev/null \
    || { echo "production restore requires openssl" >&2; exit 1; }
  openssl pkey -pubin -in "$public_key_file" -text_pub -noout 2>/dev/null \
    | grep -q 'ED25519' \
    || { echo "verification key must be an OpenSSL Ed25519 public key" >&2; exit 2; }
  [[ -n "$age_identity_file" && -f "$age_identity_file" && ! -L "$age_identity_file" && -r "$age_identity_file" ]] \
    || { echo "production restore requires a readable age identity file" >&2; exit 2; }
  grep -q '^AGE-SECRET-KEY-1' "$age_identity_file" \
    || { echo "production age identity file contains no native age identity" >&2; exit 2; }
  [[ -n "$rollback_state_file" ]] \
    || { echo "production restore requires a persistent rollback-state file" >&2; exit 2; }
fi

for numeric_setting in max_upload_object_bytes max_upload_total_bytes reserve_free_bytes; do
  value="${!numeric_setting}"
  [[ "$value" =~ ^[0-9]+$ ]] \
    || { echo "$numeric_setting must be a non-negative integer" >&2; exit 2; }
done
(( max_upload_object_bytes > 0 && max_upload_total_bytes > 0 )) \
  || { echo "restore upload byte limits must be positive" >&2; exit 2; }

test_fail_after_moves="${NORTHSTAR_RESTORE_TEST_FAIL_AFTER_UPLOAD_MOVES:-0}"
test_fail_point="${NORTHSTAR_RESTORE_TEST_FAIL_POINT:-}"
test_signal_point="${NORTHSTAR_RESTORE_TEST_SIGNAL_POINT:-}"
[[ "$test_fail_after_moves" =~ ^[0-9]+$ ]] \
  || { echo "NORTHSTAR_RESTORE_TEST_FAIL_AFTER_UPLOAD_MOVES must be a non-negative integer" >&2; exit 2; }
for test_point in "$test_fail_point" "$test_signal_point"; do
  case "$test_point" in
    ""|after-database-switch|after-first-old|after-first-new|before-commit) ;;
    *) echo "unsupported restore fault-injection point: $test_point" >&2; exit 2 ;;
  esac
done

[[ -d "$backup_dir" && ! -L "$backup_dir" ]] \
  || { echo "backup path must be a real directory" >&2; exit 2; }
backup_dir="$(cd "$backup_dir" && pwd -P)"
for command in awk bash chown chmod cmp cp createdb date du find flock grep id initdb mktemp mv \
  pg_ctl pg_dump pg_restore psql python3 rm sed sha256sum stat tar tr wc; do
  command -v "$command" >/dev/null \
    || { echo "required command is unavailable: $command" >&2; exit 1; }
done
for grant_policy_file in "$grant_boundary_sql" "$migration_ledger_manifest_sql" \
  "$capability_manifest_sql" "$grant_apply_sql"; do
  [[ -f "$grant_policy_file" && ! -L "$grant_policy_file" && -r "$grant_policy_file" ]] \
    || { echo "database grant policy is missing or unsafe: $grant_policy_file" >&2; exit 1; }
done
pg_client=(python3 "$script_dir/run-postgres.py")
if [[ -n "$database_url_file" ]]; then
  pg_client+=(--database-url-file "$database_url_file")
fi
pg_client+=(--)

[[ -d "$upload_dir" && ! -L "$upload_dir" ]] \
  || { echo "upload restore target must be a pre-created real directory: $upload_dir" >&2; exit 2; }
[[ -d "$rollback_dir" && ! -L "$rollback_dir" ]] \
  || { echo "restore rollback target must be a pre-created real directory: $rollback_dir" >&2; exit 2; }
[[ -d "$plaintext_staging_root" && ! -L "$plaintext_staging_root" ]] \
  || { echo "plaintext staging root must be a pre-created real directory" >&2; exit 2; }
resolved_upload="$(cd "$upload_dir" && pwd -P)"
resolved_rollback="$(cd "$rollback_dir" && pwd -P)"
resolved_staging="$(cd "$plaintext_staging_root" && pwd -P)"
resolved_home=""
if [[ -n "${HOME:-}" && -d "$HOME" ]]; then
  resolved_home="$(cd "$HOME" && pwd -P)"
fi
for guarded_path in "$resolved_upload" "$resolved_rollback"; do
  if [[ "$guarded_path" == "/" || "$guarded_path" == "$project_dir" ]] \
     || [[ -n "$resolved_home" && "$guarded_path" == "$resolved_home" ]]; then
    echo "refusing broad restore path: $guarded_path" >&2
    exit 2
  fi
done
paths_overlap() {
  local left="$1" right="$2"
  [[ "$left" == "$right" || "$left" == "$right"/* || "$right" == "$left"/* ]]
}
if paths_overlap "$resolved_upload" "$resolved_rollback" \
   || paths_overlap "$resolved_upload" "$backup_dir" \
   || paths_overlap "$resolved_rollback" "$backup_dir"; then
  echo "restore upload, rollback and backup directories must not overlap" >&2
  exit 2
fi

current_owner="$(id -u):$(id -g)"
require_private_state_parent() {
  local parent="$1" label="$2"
  [[ "$(stat -c '%u:%g' "$parent")" == "$current_owner" ]] \
    || { echo "$label parent must be owned by the restore account" >&2; return 1; }
  [[ "$(stat -c '%a' "$parent")" == 700 ]] \
    || { echo "$label parent must have mode 0700" >&2; return 1; }
}

# Hold the trusted-floor lock from policy evaluation through the commit point.
# Open read/write without truncation and compare the opened inode with the path,
# so a symlink swap cannot turn chmod/truncation into an arbitrary-file write.
rollback_state_lock_fd=""
if [[ -n "$rollback_state_file" ]]; then
  rollback_state_parent="$(dirname -- "$rollback_state_file")"
  [[ -d "$rollback_state_parent" && ! -L "$rollback_state_parent" ]] \
    || { echo "rollback state parent must be a pre-created real directory" >&2; exit 2; }
  rollback_state_parent="$(cd "$rollback_state_parent" && pwd -P)"
  require_private_state_parent "$rollback_state_parent" "rollback state" || exit 2
  rollback_state_file="$rollback_state_parent/$(basename -- "$rollback_state_file")"
  if paths_overlap "$rollback_state_file" "$resolved_upload" \
     || paths_overlap "$rollback_state_file" "$resolved_rollback" \
     || paths_overlap "$rollback_state_file" "$backup_dir"; then
    echo "rollback state must be outside backup, upload and rollback payload directories" >&2
    exit 2
  fi
  if [[ -e "$rollback_state_file" || -L "$rollback_state_file" ]]; then
    [[ -f "$rollback_state_file" && ! -L "$rollback_state_file" \
       && "$(stat -c '%u:%g' "$rollback_state_file")" == "$current_owner" \
       && "$(stat -c '%a' "$rollback_state_file")" == 600 ]] \
      || { echo "rollback state must be an owner-only regular non-symlink file" >&2; exit 2; }
  fi
  rollback_lock_file="$rollback_state_file.lock"
  [[ ! -L "$rollback_lock_file" ]] \
    || { echo "rollback state lock must not be a symlink" >&2; exit 2; }
  exec {rollback_state_lock_fd}>>"$rollback_lock_file"
  [[ -f "$rollback_lock_file" && ! -L "$rollback_lock_file" \
     && "$(stat -c '%u:%g' "$rollback_lock_file")" == "$current_owner" \
     && "$(stat -c '%a' "$rollback_lock_file")" == 600 \
     && "$(stat -Lc '%d:%i' "/proc/$$/fd/$rollback_state_lock_fd")" == "$(stat -c '%d:%i' "$rollback_lock_file")" ]] \
    || { echo "rollback state lock failed owner/mode/inode validation" >&2; exit 2; }
  flock -n "$rollback_state_lock_fd" \
    || { echo "another restore holds the rollback policy lock" >&2; exit 1; }
fi

upload_marker="$resolved_upload/.northstar-upload-root"
validate_upload_namespace() {
  local root="$1" allow_marker="$2" allowed_cutover="${3:-}" entry name errors=0
  local root_owner
  root_owner="$(stat -c '%u:%g' "$root")"
  while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    if [[ "$allow_marker" == true && "$name" == ".northstar-upload-root" ]]; then
      if [[ ! -f "$entry" || -L "$entry" ]] \
         || [[ "$(wc -c <"$entry" | tr -d ' ')" != 25 ]] \
         || [[ "$(<"$entry")" != "northstar-upload-root-v1" ]] \
         || [[ "$(stat -c '%u:%g' "$entry")" != "$root_owner" ]]; then
        echo "upload-root marker is malformed: $entry" >&2
        errors=$((errors + 1))
      fi
    elif [[ -n "$allowed_cutover" && "$entry" == "$allowed_cutover" \
            && -d "$entry" && ! -L "$entry" \
            && "$(stat -c '%a' "$entry")" == 700 \
            && "$(stat -c '%u:%g' "$entry")" == "$root_owner" ]]; then
      :
    elif [[ "$name" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
         && [[ -f "$entry" && ! -L "$entry" ]]; then
      if [[ "$allow_marker" == true && "$(stat -c '%a' "$entry")" != 600 ]]; then
        echo "upload object is not mode 0600: $entry" >&2
        errors=$((errors + 1))
      fi
      if [[ "$allow_marker" == true && "$(stat -c '%u:%g' "$entry")" != "$root_owner" ]]; then
        echo "upload object ownership differs from its root: $entry" >&2
        errors=$((errors + 1))
      fi
    else
      echo "unexpected object in upload root: $entry" >&2
      errors=$((errors + 1))
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -print0)
  (( errors == 0 ))
}
validate_upload_namespace "$resolved_upload" true \
  || { echo "restore refused before cutover: upload root is not a strict UUID namespace" >&2; exit 2; }
[[ -f "$upload_marker" && ! -L "$upload_marker" \
   && "$(stat -c '%a' "$resolved_upload")" == 700 \
   && "$(stat -c '%a' "$upload_marker")" == 600 \
   && "$(stat -c '%u:%g' "$upload_marker")" == "$current_owner" \
   && "$(stat -c '%u:%g' "$resolved_upload")" == "$current_owner" ]] \
  || { echo "restore refused: upload root and marker must be private and owned by this account" >&2; exit 2; }

rollback_marker="$resolved_rollback/.northstar-rollback-root"
rollback_errors=0
while IFS= read -r -d '' entry; do
  name="${entry##*/}"
  if [[ "$name" == ".northstar-rollback-root" ]]; then
    if [[ ! -f "$entry" || -L "$entry" ]] \
       || [[ "$(wc -c <"$entry" | tr -d ' ')" != 30 ]] \
       || [[ "$(<"$entry")" != "northstar-restore-rollback-v1" ]]; then
      echo "rollback-root marker is malformed: $entry" >&2
      rollback_errors=$((rollback_errors + 1))
    fi
  elif [[ "$name" =~ ^restore-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}$ ]] \
       && [[ -d "$entry" && ! -L "$entry" ]]; then
    :
  else
    echo "unexpected object in restore rollback root: $entry" >&2
    rollback_errors=$((rollback_errors + 1))
  fi
done < <(find "$resolved_rollback" -mindepth 1 -maxdepth 1 -print0)
(( rollback_errors == 0 )) \
  || { echo "restore refused before cutover: rollback root is not dedicated" >&2; exit 2; }
[[ -f "$rollback_marker" && ! -L "$rollback_marker" \
   && "$(stat -c '%a' "$resolved_rollback")" == 700 \
   && "$(stat -c '%a' "$rollback_marker")" == 600 \
   && "$(stat -c '%u:%g' "$rollback_marker")" == "$current_owner" \
   && "$(stat -c '%u:%g' "$resolved_rollback")" == "$current_owner" ]] \
  || { echo "restore refused: rollback root and marker must be private and owned by this account" >&2; exit 2; }

restore_id="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
work_dir="$(mktemp -d "$resolved_staging/northstar-restore-plaintext.XXXXXX")"
chmod 0700 "$work_dir"
extract_dir="$work_dir/uploads"
payload_dir="$work_dir/payload"
mkdir -m 0700 "$extract_dir" "$payload_dir"
cutover_dir=""
cutover_old=""
cutover_new=""
journal_file=""
old_manifest=""
new_manifest=""
rollback_set=""
previous_uploads=""
rollback_dump=""
db_session_started=false
db_session_pid=""
db_session_in=""
db_session_out=""
primary_worker_started=false
primary_worker_pid=""
primary_worker_in=""
primary_worker_out=""
compensation_worker_started=false
compensation_worker_pid=""
compensation_worker_in=""
compensation_worker_out=""
target_database=""
target_backend_pid=""
primary_backend_pid=""
compensation_backend_pid=""
incoming_outcome_marker="northstar-$restore_id-incoming"
rollback_outcome_marker="northstar-$restore_id-rollback"
last_restore_outcome=""
replacement_committed=false
database_outcome_unknown=false
restore_transaction_active=false
active_restore_barrier_key=""
active_restore_barrier_label=""
active_restore_worker=""
restore_outcome_clear_started=false
restore_outcome_cleared=false
fence_attempted=false
database_fence_active=false
database_switched=false
compensation_required=false
restore_committed=false
preserve_work=false
cleanup_running=false
last_failure_status=0

fsync_path() {
  python3 - "$1" <<'PY'
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
if path.is_dir():
    flags |= getattr(os, "O_DIRECTORY", 0)
fd = os.open(path, flags)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
}

remove_work_dir() {
  [[ ! -d "$work_dir" ]] && return 0
  case "$work_dir" in
    "$resolved_staging"/northstar-restore-plaintext.*)
      rm -rf --one-file-system -- "$work_dir"
      ;;
    *)
      echo "refusing to clean unexpected restore staging path: $work_dir" >&2
      return 1
      ;;
  esac
}

remove_cutover_dir() {
  [[ -z "$cutover_dir" || ! -d "$cutover_dir" ]] && return 0
  case "$cutover_dir" in
    "$resolved_upload"/.northstar-restore-cutover-[0-9a-f][0-9a-f]*)
      rm -rf --one-file-system -- "$cutover_dir"
      fsync_path "$resolved_upload"
      ;;
    *)
      echo "refusing to clean unexpected cutover path: $cutover_dir" >&2
      return 1
      ;;
  esac
}

journal_append() {
  [[ -n "$journal_file" && -f "$journal_file" && ! -L "$journal_file" ]] || return 1
  python3 - "$journal_file" "$@" <<'PY'
import os
import sys

path = sys.argv[1]
fields = sys.argv[2:]
if any("\t" in field or "\n" in field or "\r" in field for field in fields):
    raise SystemExit("unsafe restore journal field")
line = ("\t".join(fields) + "\n").encode("ascii")
flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    os.write(fd, line)
    os.fsync(fd)
finally:
    os.close(fd)
PY
  fsync_path "$cutover_dir"
}

object_matches() {
  local path="$1" expected_size="$2" expected_digest="$3"
  [[ -f "$path" && ! -L "$path" \
     && "$(stat -c '%s' "$path")" == "$expected_size" \
     && "$(sha256sum "$path" | awk '{print $1}')" == "$expected_digest" ]]
}

verify_manifest_objects() {
  python3 - "$1" "$2" "${3:-}" <<'PY'
import hashlib
import pathlib
import re
import stat
import sys

manifest = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
allowed_cutover = sys.argv[3] or None
uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
expected = {}
for number, raw in enumerate(manifest.read_text(encoding="ascii").splitlines(), 1):
    fields = raw.split("\t")
    if len(fields) != 3 or not uuid_re.fullmatch(fields[0]) or not fields[1].isdigit() or len(fields[2]) != 64:
        raise SystemExit(f"invalid object manifest line {number}")
    expected[fields[0]] = (int(fields[1]), fields[2])
actual = {}
for entry in root.iterdir():
    if entry.name == ".northstar-upload-root" or entry.name == allowed_cutover:
        continue
    metadata = entry.lstat()
    if not uuid_re.fullmatch(entry.name) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"unexpected object while checking manifest: {entry}")
    digest = hashlib.sha256()
    with entry.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual[entry.name] = (metadata.st_size, digest.hexdigest())
if actual != expected:
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(name for name in expected.keys() & actual.keys() if expected[name] != actual[name])
    raise SystemExit(f"object manifest mismatch: missing={missing} extra={extra} changed={changed}")
PY
}

close_psql_session() {
  local session_pid="$1" session_in="$2" session_out="$3"
  if [[ -n "$session_in" && -e "/proc/$$/fd/$session_in" ]]; then
    printf '%s\n' '\q' >&"$session_in" || true
    exec {session_in}>&- || true
  fi
  if [[ -n "$session_out" && -e "/proc/$$/fd/$session_out" ]]; then
    exec {session_out}<&- || true
  fi
  [[ -z "$session_pid" ]] || wait "$session_pid" 2>/dev/null || true
}

close_db_sessions() {
  if [[ "$primary_worker_started" == true ]]; then
    close_psql_session "$primary_worker_pid" "$primary_worker_in" "$primary_worker_out"
    primary_worker_started=false
  fi
  if [[ "$compensation_worker_started" == true ]]; then
    close_psql_session \
      "$compensation_worker_pid" "$compensation_worker_in" "$compensation_worker_out"
    compensation_worker_started=false
  fi
  if [[ "$db_session_started" == true ]]; then
    close_psql_session "$db_session_pid" "$db_session_in" "$db_session_out"
    db_session_started=false
  fi
}

abort_psql_session_for_cleanup() {
  local session_pid="$1" session_in="$2" session_out="$3" output_file="$4" line
  # Closing stdin is the transaction-safe interrupt.  psql either finishes an
  # already-buffered COMMIT or reaches EOF and disconnects, which makes
  # PostgreSQL roll back any still-open transaction.  Draining stdout lets the
  # child finish without a pipe backpressure deadlock; the catalog barrier then
  # determines which outcome actually committed.
  if [[ -n "$session_in" && -e "/proc/$$/fd/$session_in" ]]; then
    exec {session_in}>&- || return 1
  fi
  if [[ -n "$session_out" && -e "/proc/$$/fd/$session_out" ]]; then
    while IFS= read -r line <&"$session_out"; do
      printf '%s\n' "$line" >>"$output_file" || return 1
    done
    exec {session_out}<&- || return 1
  fi
  [[ -z "$session_pid" ]] || wait "$session_pid" 2>/dev/null || true
}

abort_active_restore_worker_for_cleanup() {
  local output_file="$work_dir/replace-$active_restore_barrier_label.out"
  case "$active_restore_worker" in
    primary)
      if [[ "$primary_worker_started" == true ]]; then
        abort_psql_session_for_cleanup "$primary_worker_pid" \
          "$primary_worker_in" "$primary_worker_out" "$output_file" || return 1
        primary_worker_started=false
      fi
      ;;
    compensation)
      if [[ "$compensation_worker_started" == true ]]; then
        abort_psql_session_for_cleanup "$compensation_worker_pid" \
          "$compensation_worker_in" "$compensation_worker_out" "$output_file" || return 1
        compensation_worker_started=false
      fi
      ;;
    *)
      echo "active restore transaction has no bounded worker identity" >&2
      return 1
      ;;
  esac
}

psql_session_command() {
  local session_in="$1" session_out="$2" input_file="$3" output_file="$4"
  local token="__NORTHSTAR_DONE_${restore_id}_$(python3 -c 'import secrets; print(secrets.token_hex(8))')__"
  [[ -e "/proc/$$/fd/$session_in" && -e "/proc/$$/fd/$session_out" ]] || return 1
  : >"$output_file"
  {
    cat "$input_file" &&
    printf '\n\\echo %s\n' "$token"
  } >&"$session_in" || return 1
  psql_session_wait_token "$session_out" "$token" "$output_file"
}

psql_session_wait_token() {
  local session_out="$1" token="$2" output_file="$3" line
  while IFS= read -r line <&"$session_out"; do
    if [[ "$line" == "$token" ]]; then
      return 0
    fi
    printf '%s\n' "$line" >>"$output_file"
  done
  return 1
}

db_session_command() {
  psql_session_command "$db_session_in" "$db_session_out" "$1" "$2"
}

primary_worker_command() {
  psql_session_command "$primary_worker_in" "$primary_worker_out" "$1" "$2"
}

write_grant_policy_variables() {
  local output_file="$1" grant_phase="$2"
  [[ "$target_database" =~ ^[A-Za-z0-9_.-]{1,63}$ ]] || return 2
  case "$grant_phase" in
    exact|auto) ;;
    *)
      echo "invalid restore grant phase: $grant_phase" >&2
      return 2
      ;;
  esac
  {
    printf '\\set database_name %s\n' "$target_database" &&
    printf '\\set migrator_role %s\n' "$database_migrator_role" &&
    printf '\\set runtime_role %s\n' "$database_runtime_role" &&
    printf '\\set command_role %s\n' "$database_command_role" &&
    printf '\\set backup_role %s\n' "$database_backup_role" &&
    printf '%s\n' '\set allow_bootstrap false' &&
    printf '\\set grant_phase %s\n' "$grant_phase"
  } >"$output_file"
}

preflight_current_database_recoverability() {
  local preflight_sql="$work_dir/current-database-recoverability.sql"
  local preflight_output="$work_dir/current-database-recoverability.out"

  # Prove that the current database is a repository-authenticated Northstar
  # state before taking a rollback dump or entering the cutover.  The canonical
  # grant application resolves an empty database to bootstrap, migration 0113
  # to prepare, and the complete current ledger to exact.  Every catalog and
  # ACL mutation is rolled back; an unknown, partial, or noncanonical schema
  # therefore fails closed while the original database is still untouched.
  write_grant_policy_variables "$preflight_sql" auto || return 1
  {
    printf '%s\n' 'BEGIN;'
    cat "$migration_ledger_manifest_sql"
    cat "$capability_manifest_sql"
    cat "$grant_apply_sql"
    printf '%s\n' 'ROLLBACK;'
  } >>"$preflight_sql"
  primary_worker_command "$preflight_sql" "$preflight_output" || {
    echo "restore target is not a recoverable empty, migration-0113, or current Northstar database" >&2
    return 1
  }
}

read_restore_outcome() {
  local outcome_sql="$work_dir/read-restore-outcome.sql"
  local outcome_output="$work_dir/read-restore-outcome.out" outcome_line outcome_count
  if [[ "$restore_transaction_active" == true ]]; then
    database_outcome_unknown=true
    last_restore_outcome="__UNSETTLED__"
    echo "refusing to interpret a restore marker before the replacement transaction settles" >&2
    return 2
  fi
  cat >"$outcome_sql" <<'SQL'
SELECT '__RESTORE_OUTCOME__' ||
       CASE count(*)
         WHEN 0 THEN '__ABSENT__'
         WHEN 1 THEN max(pg_catalog.substr(setting,
                            pg_catalog.length('northstar.restore_commit=') + 1))
         ELSE '__INVALID__'
       END
  FROM pg_catalog.pg_db_role_setting AS role_setting
 CROSS JOIN LATERAL pg_catalog.unnest(role_setting.setconfig) AS option(setting)
 WHERE role_setting.setdatabase = (
         SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()
       )
   AND role_setting.setrole = 0
   AND setting LIKE 'northstar.restore_commit=%';
SQL
  if ! db_session_command "$outcome_sql" "$outcome_output"; then
    database_outcome_unknown=true
    last_restore_outcome="__UNREADABLE__"
    echo "cannot determine the transactional database restore outcome" >&2
    return 2
  fi
  outcome_line="$(sed -n 's/^__RESTORE_OUTCOME__//p' "$outcome_output")"
  outcome_count="$(awk '/^__RESTORE_OUTCOME__/ { count += 1 } END { print count + 0 }' \
    "$outcome_output")"
  if [[ -z "$outcome_line" || "$outcome_count" != 1 ]]; then
    database_outcome_unknown=true
    last_restore_outcome="__INVALID__"
    echo "database restore outcome catalog returned an ambiguous result" >&2
    return 2
  fi
  last_restore_outcome="$outcome_line"
  case "$last_restore_outcome" in
    __ABSENT__|"$incoming_outcome_marker"|"$rollback_outcome_marker") return 0 ;;
    *)
      database_outcome_unknown=true
      echo "database contains an unrecognized restore outcome marker" >&2
      return 2
      ;;
  esac
}

clear_restore_outcome() {
  local expected_marker="$1"
  local clear_sql="$work_dir/clear-restore-outcome.sql"
  if ! read_restore_outcome || [[ "$last_restore_outcome" != "$expected_marker" ]]; then
    database_outcome_unknown=true
    echo "refusing to clear a restore outcome other than the expected committed marker" >&2
    return 1
  fi
  cat >"$clear_sql" <<SQL
\\set target_db $target_database
SET synchronous_commit TO on;
SELECT format('ALTER DATABASE %I RESET northstar.restore_commit', :'target_db') \gexec
SQL
  db_session_command "$clear_sql" "$work_dir/clear-restore-outcome.out" || return 1
  if ! read_restore_outcome || [[ "$last_restore_outcome" != __ABSENT__ ]]; then
    database_outcome_unknown=true
    echo "database restore outcome marker was not cleared exactly" >&2
    return 1
  fi
}

wait_for_restore_transaction_barrier() {
  local barrier_key="$1" label="$2"
  local barrier_sql="$work_dir/$label-transaction-barrier.sql"
  local barrier_output="$work_dir/$label-transaction-barrier.out"
  [[ "$barrier_key" =~ ^northstar-restore-[0-9a-f]{32}-(incoming|rollback)$ ]] || return 2
  {
    printf '\\set restore_barrier_key %s\n' "$barrier_key" &&
    printf '%s\n' 'BEGIN;' &&
    printf "%s\n" \
      "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0));" &&
    printf '%s\n' 'COMMIT;'
  } >"$barrier_sql"
  db_session_command "$barrier_sql" "$barrier_output" || {
    database_outcome_unknown=true
    echo "cannot establish that the $label replacement transaction has ended" >&2
    return 1
  }
}

settle_active_restore_transaction() {
  if [[ "$restore_transaction_active" != true ]]; then
    return 0
  fi
  if [[ -z "$active_restore_barrier_key" || -z "$active_restore_barrier_label" ]]; then
    database_outcome_unknown=true
    echo "active restore transaction has no verifiable barrier identity" >&2
    return 1
  fi
  if [[ "$cleanup_running" == true ]]; then
    # A signal can interrupt the producer before it has sent ROLLBACK or COMMIT.
    # End that exact pre-opened worker first, otherwise it may remain idle in a
    # transaction waiting for stdin while the control connection waits forever
    # on its transaction lock.
    if ! abort_active_restore_worker_for_cleanup; then
      database_outcome_unknown=true
      return 1
    fi
  fi
  if ! wait_for_restore_transaction_barrier \
    "$active_restore_barrier_key" "$active_restore_barrier_label"; then
    database_outcome_unknown=true
    return 1
  fi
  restore_transaction_active=false
  active_restore_barrier_key=""
  active_restore_barrier_label=""
  active_restore_worker=""
}

initialize_restore_worker() {
  local label="$1" session_in="$2" session_out="$3" output_file="$4" result_variable="$5"
  local init_sql="$work_dir/$label-worker-init.sql" worker_database worker_pid
  cat >"$init_sql" <<SQL
SET application_name TO 'northstar-restore-$restore_id-$label';
SELECT '__DATABASE__' || current_database();
SELECT '__BACKEND_PID__' || pg_backend_pid()::text;
SQL
  psql_session_command "$session_in" "$session_out" "$init_sql" "$output_file" || return 1
  worker_database="$(sed -n 's/^__DATABASE__//p' "$output_file")"
  worker_pid="$(sed -n 's/^__BACKEND_PID__//p' "$output_file")"
  [[ "$worker_database" == "$target_database" && "$worker_pid" =~ ^[0-9]+$ ]] \
    || { echo "$label restore worker has an unsafe database identity" >&2; return 1; }
  printf -v "$result_variable" '%s' "$worker_pid"
}

start_db_sessions() {
  local init_sql="$work_dir/db-session-init.sql" init_output="$work_dir/db-session-init.out"
  local grant_check_sql="$work_dir/grant-boundary-check.sql"
  local grant_check_output="$work_dir/grant-boundary-check.out"
  coproc RESTORE_DB_SESSION {
    "${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
  }
  db_session_out="${RESTORE_DB_SESSION[0]}"
  db_session_in="${RESTORE_DB_SESSION[1]}"
  db_session_pid="$RESTORE_DB_SESSION_PID"
  db_session_started=true
  cat >"$init_sql" <<SQL
SET application_name TO 'northstar-restore-$restore_id';
SELECT CASE WHEN pg_try_advisory_lock($maintenance_lock_key)
       THEN '__LOCK_OK__' ELSE '__LOCK_BUSY__' END;
SELECT '__DATABASE__' || current_database();
SELECT '__BACKEND_PID__' || pg_backend_pid()::text;
SQL
  db_session_command "$init_sql" "$init_output" || return 1
  grep -qx '__LOCK_OK__' "$init_output" \
    || { echo "another backup or restore holds the PostgreSQL maintenance fence" >&2; return 1; }
  target_database="$(sed -n 's/^__DATABASE__//p' "$init_output")"
  target_backend_pid="$(sed -n 's/^__BACKEND_PID__//p' "$init_output")"
  [[ "$target_database" =~ ^[A-Za-z0-9_.-]{1,63}$ \
     && "$target_database" != postgres \
     && "$target_database" != template0 \
     && "$target_database" != template1 \
     && "$target_backend_pid" =~ ^[0-9]+$ ]] \
    || { echo "restore target database name or backend identity is not safely manageable" >&2; return 1; }

  # Policy application and dump replacement deliberately run on disposable
  # workers.  The maintenance session above remains alive solely to own the
  # advisory lock and read the transactionally committed outcome marker.
  coproc PRIMARY_RESTORE_WORKER {
    "${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
  }
  primary_worker_out="${PRIMARY_RESTORE_WORKER[0]}"
  primary_worker_in="${PRIMARY_RESTORE_WORKER[1]}"
  primary_worker_pid="$PRIMARY_RESTORE_WORKER_PID"
  primary_worker_started=true
  initialize_restore_worker primary "$primary_worker_in" "$primary_worker_out" \
    "$work_dir/primary-worker-init.out" primary_backend_pid || return 1

  [[ "$target_backend_pid" != "$primary_backend_pid" ]] \
    || { echo "restore database sessions do not have distinct backend identities" >&2; return 1; }

  if ! read_restore_outcome || [[ "$last_restore_outcome" != __ABSENT__ ]]; then
    echo "restore refused: the target database has an unresolved prior restore outcome" >&2
    return 1
  fi

  # Fail before taking the hard connection fence if the URL is not the
  # non-superuser migrator owner or the workload-role boundary has drifted.
  write_grant_policy_variables "$grant_check_sql" exact || return 1
  cat "$grant_boundary_sql" >>"$grant_check_sql"
  primary_worker_command "$grant_check_sql" "$grant_check_output" || {
    echo "restore requires the verified Northstar migrator/role boundary" >&2
    return 1
  }
  preflight_current_database_recoverability
}

start_compensation_worker() {
  coproc COMPENSATION_RESTORE_WORKER {
    "${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align --set ON_ERROR_STOP=1
  }
  compensation_worker_out="${COMPENSATION_RESTORE_WORKER[0]}"
  compensation_worker_in="${COMPENSATION_RESTORE_WORKER[1]}"
  compensation_worker_pid="$COMPENSATION_RESTORE_WORKER_PID"
  compensation_worker_started=true
  initialize_restore_worker compensation "$compensation_worker_in" "$compensation_worker_out" \
    "$work_dir/compensation-worker-init.out" compensation_backend_pid || return 1
  [[ "$target_backend_pid" != "$compensation_backend_pid" \
     && "$primary_backend_pid" != "$compensation_backend_pid" ]] \
    || { echo "restore database sessions do not have distinct backend identities" >&2; return 1; }
}

set_database_connections() {
  local enabled="$1"
  local sql_file="$work_dir/database-connections-$enabled.sql"
  local output_file="$work_dir/database-connections-$enabled.out"
  [[ "$enabled" == true || "$enabled" == false ]] || return 2
  {
    printf '\\set target_db %s\n' "$target_database"
    printf '%s\n' 'SET synchronous_commit TO on;'
    printf "SELECT format('ALTER DATABASE %%I WITH ALLOW_CONNECTIONS %s', :'target_db') \\\\gexec\n" \
      "$enabled"
  } >"$sql_file"
  db_session_command "$sql_file" "$output_file"
}

activate_database_fence() {
  local sql_file="$work_dir/database-fence.sql" session_counts remaining_sessions allowed_sessions
  fence_attempted=true
  set_database_connections false
  cat >"$sql_file" <<SQL
\\set target_db $target_database
\\set control_pid $target_backend_pid
\\set primary_pid $primary_backend_pid
\\set compensation_pid $compensation_backend_pid
SELECT COUNT(*) FILTER (
         WHERE pid NOT IN (:control_pid, :primary_pid, :compensation_pid)
       )::text || ':' ||
       COUNT(*) FILTER (
         WHERE pid IN (:control_pid, :primary_pid, :compensation_pid)
       )::text
FROM pg_stat_activity
WHERE datname = :'target_db';
SQL
  db_session_command "$sql_file" "$work_dir/database-fence.out" || return 1
  session_counts="$(sed -n '/^[0-9][0-9]*:[0-9][0-9]*$/p' "$work_dir/database-fence.out")"
  [[ "$session_counts" =~ ^[0-9]+:[0-9]+$ ]] \
    || { echo "failed to identify the exact restore database sessions" >&2; return 1; }
  IFS=: read -r remaining_sessions allowed_sessions <<<"$session_counts"
  if (( remaining_sessions != 0 || allowed_sessions != 3 )); then
    echo "restore refused: $remaining_sessions other target database session(s) remain after the connection fence; stop Northstar and all database clients, then retry" >&2
    return 1
  fi
  database_fence_active=true
  journal_append fence-active "$target_database" "$target_backend_pid" \
    "$primary_backend_pid" "$compensation_backend_pid"
}

release_database_fence() {
  if [[ "$fence_attempted" != true ]]; then
    return 0
  fi
  if [[ "$restore_transaction_active" == true ]]; then
    database_outcome_unknown=true
    echo "refusing to release the database fence while a replacement transaction is unsettled" >&2
    return 1
  fi
  if [[ "$database_outcome_unknown" == true ]]; then
    echo "refusing to release the database fence while the restore outcome is unknown" >&2
    return 1
  fi
  if [[ "$restore_committed" == true && "$restore_outcome_cleared" != true ]]; then
    database_outcome_unknown=true
    echo "refusing to release the database fence before retiring the committed restore marker" >&2
    return 1
  fi
  set_database_connections true
  database_fence_active=false
  fence_attempted=false
}

replace_database_from_dump() {
  local replacement_dump="$1" label="$2" grant_phase="$3"
  local worker_in="$4" worker_out="$5" expected_marker="$6" prior_marker="$7"
  local output_file="$work_dir/replace-$label.out"
  local grant_variables="$work_dir/replace-$label-grant-variables.sql"
  local nonce ready_token token barrier_key worker_kind
  local header_ok=true ready_ok=false stream_ok=true token_ok=false
  nonce="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
  ready_token="__NORTHSTAR_RESTORE_READY_${label}_${restore_id}_${nonce}__"
  token="__NORTHSTAR_RESTORE_DONE_${label}_${restore_id}_${nonce}__"
  replacement_committed=false
  [[ -e "/proc/$$/fd/$worker_in" && -e "/proc/$$/fd/$worker_out" ]] || return 1
  [[ "$expected_marker" =~ ^northstar-[0-9a-f]{32}-(incoming|rollback)$ \
     && "$prior_marker" != "$expected_marker" ]] || return 2
  [[ "$prior_marker" == __ABSENT__ \
     || "$prior_marker" =~ ^northstar-[0-9a-f]{32}-(incoming|rollback)$ ]] || return 2
  case "$expected_marker" in
    *-incoming)
      barrier_key="northstar-restore-$restore_id-incoming"
      worker_kind=primary
      [[ "$worker_in" == "$primary_worker_in" && "$worker_out" == "$primary_worker_out" ]] \
        || return 2
      ;;
    *-rollback)
      barrier_key="northstar-restore-$restore_id-rollback"
      worker_kind=compensation
      [[ "$worker_in" == "$compensation_worker_in" \
         && "$worker_out" == "$compensation_worker_out" ]] || return 2
      ;;
    *) return 2 ;;
  esac
  write_grant_policy_variables "$grant_variables" "$grant_phase" || return 1
  {
    printf '\\set restore_outcome_marker %s\n' "$expected_marker" &&
    printf '\\set prior_restore_outcome %s\n' "$prior_marker" &&
    printf '\\set restore_barrier_key %s\n' "$barrier_key"
  } >>"$grant_variables"
  : >"$output_file"

  if [[ "$restore_transaction_active" == true ]]; then
    database_outcome_unknown=true
    echo "refusing to overlap database replacement transactions" >&2
    return 2
  fi
  restore_transaction_active=true
  active_restore_barrier_key="$barrier_key"
  active_restore_barrier_label="$label"
  active_restore_worker="$worker_kind"

  # Phase one establishes a transaction boundary before any destructive SQL is
  # sent.  READY proves that the worker owns the unique transaction-level lock
  # and that the required prior outcome still matches the catalog.
  {
    cat "$grant_variables" &&
    printf '%s\n' 'BEGIN;' &&
    printf "%s\n" \
      "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0));" &&
    cat <<'SQL'
SELECT (
         CASE count(*)
           WHEN 0 THEN '__ABSENT__'
           WHEN 1 THEN max(pg_catalog.substr(setting,
                              pg_catalog.length('northstar.restore_commit=') + 1))
           ELSE '__INVALID__'
         END
       ) = :'prior_restore_outcome' AS northstar_prior_restore_outcome_matches
  FROM pg_catalog.pg_db_role_setting AS role_setting
 CROSS JOIN LATERAL pg_catalog.unnest(role_setting.setconfig) AS option(setting)
 WHERE role_setting.setdatabase = (
         SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()
       )
   AND role_setting.setrole = 0
   AND setting LIKE 'northstar.restore_commit=%' \gset
\if :northstar_prior_restore_outcome_matches
\else
  \echo 'restore outcome changed before the replacement transaction'
  \quit 44
\endif
SQL
    printf '\\echo %s\n' "$ready_token"
  } >&"$worker_in" || header_ok=false
  if [[ "$header_ok" == true ]] \
    && psql_session_wait_token "$worker_out" "$ready_token" "$output_file"; then
    ready_ok=true
  fi
  if [[ "$ready_ok" != true ]]; then
    {
      printf '%s\n' 'ROLLBACK;' &&
      printf '\\echo %s\n' "$token"
    } >&"$worker_in" 2>/dev/null || true
    psql_session_wait_token "$worker_out" "$token" "$output_file" 2>/dev/null || true
    settle_active_restore_transaction || return 2
    if ! read_restore_outcome; then
      return 2
    fi
    if [[ "$last_restore_outcome" == "$prior_marker" ]]; then
      echo "$label database replacement failed before its destructive phase" >&2
      return 1
    fi
    database_outcome_unknown=true
    echo "$label database replacement failed READY with an unknown outcome" >&2
    return 2
  fi

  # Phase two is unreachable until READY.  The advisory transaction lock stays
  # held through schema replacement, ACL convergence, marker write and COMMIT.
  {
    cat <<'SQL'
DO $northstar_restore$
DECLARE user_schema record;
BEGIN
  FOR user_schema IN
    SELECT nspname FROM pg_namespace
    WHERE nspname <> 'information_schema'
      AND nspname !~ '^pg_'
  LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', user_schema.nspname);
  END LOOP;
  EXECUTE format('CREATE SCHEMA public AUTHORIZATION %I', current_user);
  EXECUTE 'REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC';
END
$northstar_restore$;
SQL
  } >&"$worker_in" || stream_ok=false
  if [[ "$stream_ok" == true ]] \
    && ! "${pg_client[@]}" pg_restore "$replacement_dump" \
      --clean --if-exists --no-owner --no-acl --file=- >&"$worker_in"; then
    stream_ok=false
  fi
  if [[ "$stream_ok" == true ]] \
    && { ! cat "$migration_ledger_manifest_sql" >&"$worker_in" \
      || ! cat "$capability_manifest_sql" >&"$worker_in" \
      || ! cat "$grant_apply_sql" >&"$worker_in"; }; then
    stream_ok=false
  fi
  if [[ "$stream_ok" == true ]]; then
    {
      printf '%s\n' 'SET LOCAL synchronous_commit TO on;' &&
      printf "SELECT format('ALTER DATABASE %%I SET northstar.restore_commit TO %%L', :'database_name', :'restore_outcome_marker') \\gexec\n" &&
      printf '%s\n' 'COMMIT;' &&
      printf '\\echo %s\n' "$token"
    } >&"$worker_in" || stream_ok=false
  fi
  if [[ "$stream_ok" != true ]]; then
    {
      printf '%s\n' 'ROLLBACK;'
      printf '\\echo %s\n' "$token"
    } >&"$worker_in" 2>/dev/null || true
  fi
  if psql_session_wait_token "$worker_out" "$token" "$output_file"; then
    token_ok=true
  fi

  # EOF does not prove that PostgreSQL has stopped processing already-buffered
  # COMMIT input.  Acquiring the worker's transaction lock on the control
  # session is the deterministic end-of-transaction barrier; only after that
  # may the catalog marker be interpreted.
  settle_active_restore_transaction || return 2
  if ! read_restore_outcome; then
    return 2
  fi
  if [[ "$last_restore_outcome" == "$expected_marker" ]]; then
    replacement_committed=true
    [[ "$token_ok" == true ]] || {
      echo "$label database replacement committed, but its worker terminated before acknowledgement" >&2
      return 1
    }
    return 0
  fi
  if [[ "$last_restore_outcome" == "$prior_marker" ]]; then
    return 1
  fi
  database_outcome_unknown=true
  echo "$label database replacement ended with an unknown transactional outcome" >&2
  return 2
}

rollback_uploads_from_journal() {
  local entries=() record object_id object_size object_digest live_path stage_path index
  local failed=false
  [[ -f "$journal_file" ]] || return 1

  mapfile -t entries < <(awk -F '\t' '$1 == "new-intent" { print $2 "\t" $3 "\t" $4 }' "$journal_file")
  for (( index=${#entries[@]}-1; index>=0; index-- )); do
    record="${entries[$index]}"
    IFS=$'\t' read -r object_id object_size object_digest <<<"$record"
    live_path="$resolved_upload/$object_id"
    stage_path="$cutover_new/$object_id"
    if [[ -e "$live_path" || -L "$live_path" ]]; then
      if [[ -e "$stage_path" || -L "$stage_path" ]] \
         || ! object_matches "$live_path" "$object_size" "$object_digest"; then
        echo "cannot compensate exact activated object: $object_id" >&2
        failed=true
      else
        mv -- "$live_path" "$stage_path" || failed=true
        fsync_path "$resolved_upload" || failed=true
        fsync_path "$cutover_new" || failed=true
      fi
    elif ! object_matches "$stage_path" "$object_size" "$object_digest"; then
      echo "activated object is missing from both exact journal locations: $object_id" >&2
      failed=true
    fi
  done

  mapfile -t entries < <(awk -F '\t' '$1 == "old-intent" { print $2 "\t" $3 "\t" $4 }' "$journal_file")
  for (( index=${#entries[@]}-1; index>=0; index-- )); do
    record="${entries[$index]}"
    IFS=$'\t' read -r object_id object_size object_digest <<<"$record"
    live_path="$resolved_upload/$object_id"
    stage_path="$cutover_old/$object_id"
    if [[ -e "$stage_path" || -L "$stage_path" ]]; then
      if [[ -e "$live_path" || -L "$live_path" ]] \
         || ! object_matches "$stage_path" "$object_size" "$object_digest"; then
        echo "cannot compensate exact previous object: $object_id" >&2
        failed=true
      else
        mv -- "$stage_path" "$live_path" || failed=true
        fsync_path "$resolved_upload" || failed=true
        fsync_path "$cutover_old" || failed=true
      fi
    elif ! object_matches "$live_path" "$object_size" "$object_digest"; then
      echo "previous object is missing from both exact journal locations: $object_id" >&2
      failed=true
    fi
  done

  if [[ "$failed" == false ]]; then
    verify_manifest_objects "$old_manifest" "$resolved_upload" "${cutover_dir##*/}" || failed=true
  fi
  [[ "$failed" == false ]]
}

compensate_restore() {
  local upload_ok=true database_ok=true journal_ok=true replacement_ok=true
  echo "restore did not commit; compensating exact journaled changes while PostgreSQL remains fenced" >&2
  if [[ "$restore_transaction_active" == true ]]; then
    database_outcome_unknown=true
    echo "cannot compensate while a replacement transaction is unsettled" >&2
    return 1
  fi
  if [[ "$database_outcome_unknown" == true ]]; then
    echo "restore outcome is unknown; preserving both planes and the hard database fence" >&2
    return 1
  fi
  if [[ "$database_switched" == true ]]; then
    replacement_committed=false
    if ! replace_database_from_dump "$rollback_dump" rollback auto \
      "$compensation_worker_in" "$compensation_worker_out" \
      "$rollback_outcome_marker" "$incoming_outcome_marker"; then
      replacement_ok=false
    fi
    if [[ "$replacement_committed" == true ]]; then
      clear_restore_outcome "$rollback_outcome_marker" || database_ok=false
    else
      database_ok=false
    fi
    [[ "$replacement_ok" == true || "$replacement_committed" == true ]] || database_ok=false
  fi
  if [[ "$database_ok" == true && -n "$cutover_dir" && -d "$cutover_dir" ]]; then
    rollback_uploads_from_journal || upload_ok=false
  fi
  if [[ "$upload_ok" == true && "$database_ok" == true ]]; then
    journal_append compensated || journal_ok=false
  fi
  [[ "$upload_ok" == true && "$database_ok" == true && "$journal_ok" == true ]]
}

on_error() {
  last_failure_status="$1"
}

finish_restore() {
  local status="$1" compensation_ok=true fence_ok=true cleanup_ok=true
  [[ "$cleanup_running" == false ]] || exit "$status"
  cleanup_running=true
  trap - ERR EXIT
  trap '' INT TERM
  set +e

  if [[ "$restore_committed" == true ]]; then
    # The replay floor has made the new data plane authoritative, so cleanup
    # must never compensate it.  It must still prove that no worker transaction
    # is active and retire this restore's exact marker before reopening the
    # database.  An interrupt during marker clearing can observe either the
    # expected marker or ABSENT only after clear was durably attempted.
    if ! settle_active_restore_transaction; then
      database_outcome_unknown=true
    elif [[ "$database_outcome_unknown" != true ]] && read_restore_outcome; then
      case "$last_restore_outcome" in
        "$incoming_outcome_marker")
          restore_outcome_clear_started=true
          if clear_restore_outcome "$incoming_outcome_marker"; then
            restore_outcome_cleared=true
          else
            database_outcome_unknown=true
          fi
          ;;
        __ABSENT__)
          if [[ "$restore_outcome_clear_started" == true ]]; then
            restore_outcome_cleared=true
          else
            database_outcome_unknown=true
            echo "committed restore outcome disappeared before exact clearing" >&2
          fi
          ;;
        *) database_outcome_unknown=true ;;
      esac
    else
      database_outcome_unknown=true
    fi
  elif [[ "$compensation_required" == true ]]; then
    if ! settle_active_restore_transaction; then
      database_outcome_unknown=true
    elif read_restore_outcome; then
      case "$last_restore_outcome" in
        "$incoming_outcome_marker") database_switched=true ;;
        __ABSENT__) database_switched=false ;;
        *) database_outcome_unknown=true ;;
      esac
    else
      database_outcome_unknown=true
    fi
    compensate_restore || compensation_ok=false
  fi

  if [[ "$fence_attempted" == true ]]; then
    if [[ "$database_outcome_unknown" == true ]]; then
      fence_ok=false
      echo "PostgreSQL remains fail-closed because the restore outcome is unknown." >&2
    elif [[ "$compensation_ok" == true || "$restore_committed" == true ]]; then
      release_database_fence || fence_ok=false
    else
      fence_ok=false
      echo "PostgreSQL remains fail-closed because compensation was incomplete." >&2
    fi
  fi
  close_db_sessions

  if [[ "$compensation_ok" == true && "$fence_ok" == true ]]; then
    if [[ "$restore_committed" != true ]]; then
      remove_cutover_dir || cleanup_ok=false
    fi
    remove_work_dir || cleanup_ok=false
  else
    preserve_work=true
    status=1
    echo "RECOVERY REQUIRED: preserved plaintext work directory: $work_dir" >&2
    [[ -z "$cutover_dir" ]] \
      || echo "RECOVERY REQUIRED: preserved durable cutover journal: $cutover_dir" >&2
    [[ -z "$rollback_dump" ]] \
      || echo "RECOVERY REQUIRED: pre-restore database dump: $rollback_dump" >&2
  fi

  if [[ "$cleanup_ok" != true ]]; then
    status=1
  fi
  if (( status == 0 && last_failure_status != 0 )); then
    status="$last_failure_status"
  fi
  exit "$status"
}

trap 'on_error $?' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'finish_restore $?' EXIT

require_available_space() {
  python3 - "$1" "$2" "$reserve_free_bytes" "$3" <<'PY'
import pathlib
import shutil
import sys

path = pathlib.Path(sys.argv[1])
needed = int(sys.argv[2])
reserve = int(sys.argv[3])
label = sys.argv[4]
available = shutil.disk_usage(path).free
if available < needed + reserve:
    raise SystemExit(
        f"insufficient free space for {label}: available={available} "
        f"required_payload={needed} reserve={reserve}"
    )
PY
}

backup_stored_bytes="$(du -sb "$backup_dir" | awk '{print $1}')"
require_available_space "$resolved_staging" "$backup_stored_bytes" "backup materialization"

verify_args=("$backup_dir" --materialize-dir "$payload_dir")
[[ -n "$public_key_file" ]] && verify_args+=(--public-key-file "$public_key_file")
[[ "$require_signature" == true ]] && verify_args+=(--require-signature)
[[ -n "$age_identity_file" ]] && verify_args+=(--age-identity-file "$age_identity_file")
[[ -n "$rollback_state_file" ]] && verify_args+=(--rollback-state-file "$rollback_state_file")
[[ "$allow_rollback" == true ]] && verify_args+=(--allow-rollback)
[[ "$allow_generation_change" == true ]] && verify_args+=(--allow-generation-change)
[[ "$security_policy" == development-legacy ]] && verify_args+=(--development-insecure-legacy)
bash "$script_dir/verify-backup.sh" "${verify_args[@]}"

read -r upload_member_count upload_total_bytes upload_largest_bytes \
  < <(python3 - "$payload_dir/uploads.tar.gz" "$max_upload_object_bytes" "$max_upload_total_bytes" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
single_limit = int(sys.argv[2])
total_limit = int(sys.argv[3])
count = total = largest = 0
with tarfile.open(archive_path, mode="r:gz") as archive:
    for member in archive:
        if not member.isfile():
            continue
        count += 1
        if member.size > single_limit:
            raise SystemExit(
                f"upload archive object exceeds limit: {member.name} "
                f"size={member.size} limit={single_limit}"
            )
        total += member.size
        largest = max(largest, member.size)
        if total > total_limit:
            raise SystemExit(
                f"upload archive expanded size exceeds limit: total={total} limit={total_limit}"
            )
print(count, total, largest)
PY
)
[[ "$upload_member_count" =~ ^[0-9]+$ && "$upload_total_bytes" =~ ^[0-9]+$ \
   && "$upload_largest_bytes" =~ ^[0-9]+$ ]] \
  || { echo "failed to calculate upload archive budgets" >&2; exit 1; }
require_available_space "$resolved_staging" "$upload_total_bytes" "upload extraction"
require_available_space "$resolved_upload" "$upload_total_bytes" "same-filesystem cutover staging"

tar --extract --gzip --file="$payload_dir/uploads.tar.gz" --directory="$extract_dir"
validate_upload_namespace "$extract_dir" false \
  || { echo "restore refused before cutover: staged uploads left the UUID namespace" >&2; exit 1; }
find "$extract_dir" -mindepth 1 -maxdepth 1 -type f -exec chmod 0600 {} +
find "$extract_dir" -mindepth 1 -maxdepth 1 -type f \
  -exec chown --reference="$resolved_upload" {} +

query_current_upload_rows() {
  local output="$1" sql_file="$work_dir/current-upload-query.sql"
  cat >"$sql_file" <<'SQL'
SELECT id || E'\t' || size::text || E'\t' || COALESCE(encode(content_sha256,'hex'),'')
FROM public.upload_slots WHERE uploaded AND expires_at > clock_timestamp() ORDER BY id;
SQL
  primary_worker_command "$sql_file" "$output"
}

validate_upload_rows_file() {
  local rows_file="$1" validation_root="$2" validation_errors=0
  local upload_id expected_size expected_digest path actual_digest
  while IFS=$'\t' read -r upload_id expected_size expected_digest; do
    [[ -n "$upload_id" ]] || continue
    if [[ ! "$upload_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
       || [[ ! "$expected_size" =~ ^[0-9]+$ ]] \
       || { [[ -n "$expected_digest" ]] && [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; }; then
      echo "restored upload metadata is malformed: $upload_id" >&2
      validation_errors=$((validation_errors + 1))
      continue
    fi
    path="$validation_root/$upload_id"
    if [[ ! -f "$path" || -L "$path" || "$(stat -c '%s' "$path")" != "$expected_size" ]]; then
      echo "restored upload is missing, linked, or has the wrong size: $upload_id" >&2
      validation_errors=$((validation_errors + 1))
      continue
    fi
    if [[ -n "$expected_digest" ]]; then
      actual_digest="$(sha256sum "$path" | awk '{print $1}')"
      if [[ "$actual_digest" != "$expected_digest" ]]; then
        echo "restored upload has the wrong SHA-256 digest: $upload_id" >&2
        validation_errors=$((validation_errors + 1))
      fi
    fi
  done <"$rows_file"
  (( validation_errors == 0 ))
}

# Restore into a private, Unix-socket-only temporary PostgreSQL instance before
# touching either production plane. The migrator URL is never used to create or
# drop a validation database on the target cluster.
validation_rows="$work_dir/validation-upload-rows.tsv"
bash "$script_dir/validate-backup-dump-local.sh" \
  "$payload_dir/database.dump" "$work_dir" "$validation_rows"
if ! validate_upload_rows_file "$validation_rows" "$extract_dir"; then
  echo "restore preflight failed; the target database and uploads were not changed" >&2
  exit 1
fi

write_object_manifest() {
  python3 - "$1" "$2" <<'PY'
import hashlib
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
rows = []
for entry in root.iterdir():
    if entry.name == ".northstar-upload-root":
        continue
    metadata = entry.lstat()
    if not uuid_re.fullmatch(entry.name) or not stat.S_ISREG(metadata.st_mode):
        raise SystemExit(f"object manifest rejected unexpected entry: {entry}")
    digest = hashlib.sha256()
    with entry.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    rows.append((entry.name, metadata.st_size, digest.hexdigest()))
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
fd = os.open(output, flags, 0o600)
try:
    with os.fdopen(fd, "w", encoding="ascii", closefd=False) as handle:
        for name, size, digest in sorted(rows):
            handle.write(f"{name}\t{size}\t{digest}\n")
        handle.flush()
        os.fsync(handle.fileno())
finally:
    os.close(fd)
PY
}

old_manifest_work="$work_dir/old-objects.tsv"
new_manifest_work="$work_dir/new-objects.tsv"
write_object_manifest "$resolved_upload" "$old_manifest_work"
write_object_manifest "$extract_dir" "$new_manifest_work"
old_total_bytes="$(awk -F '\t' '{ total += $2 } END { printf "%.0f", total + 0 }' "$old_manifest_work")"
database_size="$("${pg_client[@]}" psql --no-psqlrc --quiet --tuples-only --no-align \
  --set ON_ERROR_STOP=1 --command='SELECT pg_database_size(current_database())')"
database_size="${database_size//[[:space:]]/}"
[[ "$database_size" =~ ^[0-9]+$ ]] || { echo "failed to determine target database size" >&2; exit 1; }
rollback_budget="$(python3 -c 'import sys; print(int(sys.argv[1]) + int(sys.argv[2]))' "$old_total_bytes" "$database_size")"
require_available_space "$resolved_rollback" "$rollback_budget" "rollback retention"

# The private cutover area is inside the upload filesystem, so every live
# rename is atomic. It contains only expanded upload objects and hash metadata;
# decrypted database payloads remain in the plaintext staging root.
cutover_dir="$resolved_upload/.northstar-restore-cutover-$restore_id"
cutover_old="$cutover_dir/old"
cutover_new="$cutover_dir/new"
mkdir -m 0700 "$cutover_dir" "$cutover_old" "$cutover_new"
old_manifest="$cutover_dir/old-objects.tsv"
new_manifest="$cutover_dir/new-objects.tsv"
cp -- "$old_manifest_work" "$old_manifest"
cp -- "$new_manifest_work" "$new_manifest"
chmod 0600 "$old_manifest" "$new_manifest"
journal_file="$cutover_dir/journal.tsv"
printf '%s\n' "format\tnorthstar-restore-journal-v1\t$restore_id" >"$journal_file"
chmod 0600 "$journal_file"
fsync_path "$old_manifest"
fsync_path "$new_manifest"
fsync_path "$journal_file"
fsync_path "$cutover_dir"
fsync_path "$resolved_upload"

while IFS=$'\t' read -r object_id object_size object_digest; do
  [[ -n "$object_id" ]] || continue
  cp -- "$extract_dir/$object_id" "$cutover_new/$object_id"
  chmod 0600 "$cutover_new/$object_id"
  chown --reference="$resolved_upload" "$cutover_new/$object_id"
  cmp -s -- "$extract_dir/$object_id" "$cutover_new/$object_id" \
    || { echo "same-filesystem staging copy verification failed: $object_id" >&2; exit 1; }
  fsync_path "$cutover_new/$object_id"
done <"$new_manifest"
fsync_path "$cutover_new"
verify_manifest_objects "$new_manifest" "$cutover_new"
journal_append staged "$upload_member_count" "$upload_total_bytes" "$upload_largest_bytes"

rollback_set="$resolved_rollback/restore-$(date -u +%Y%m%dT%H%M%SZ)-$restore_id"
mkdir -m 0700 "$rollback_set"
previous_uploads="$rollback_set/uploads"
mkdir -m 0700 "$previous_uploads"
fsync_path "$resolved_rollback"
rollback_dump="$rollback_set/database-before.dump"

# The persistent session owns the advisory maintenance fence used by backup and
# restore. A hard database connection fence is installed immediately before
# replacement; the advisory fence alone is not represented as an application
# writer lock.
start_db_sessions
"${pg_client[@]}" pg_dump --format=custom --compress=9 --no-owner --no-acl \
  --file="$rollback_dump"
chmod 0600 "$rollback_dump"
"${pg_client[@]}" pg_restore --list "$rollback_dump" >/dev/null
fsync_path "$rollback_dump"
fsync_path "$rollback_set"
journal_append rollback-ready "$rollback_set"

# ALLOW_CONNECTIONS=false is the fail-closed boundary. The restore does not
# terminate sessions: operators must stop the application and all clients first.
# The independent compensation worker is opened before the fence, so it remains
# available even if the primary replacement worker terminates on a SQL error. A
# crash leaves the target unavailable rather than exposing a half-switched data
# plane.
start_compensation_worker
activate_database_fence
verify_manifest_objects "$old_manifest" "$resolved_upload" "${cutover_dir##*/}" \
  || { echo "upload root changed while the database fence was being installed" >&2; exit 1; }
compensation_required=true
journal_append database-switch-intent
replacement_committed=false
if ! replace_database_from_dump "$payload_dir/database.dump" restored exact \
  "$primary_worker_in" "$primary_worker_out" \
  "$incoming_outcome_marker" __ABSENT__; then
  database_switched="$replacement_committed"
  false
fi
database_switched="$replacement_committed"
journal_append database-switch-done

inject_at() {
  local point="$1"
  if [[ "$test_signal_point" == "$point" ]]; then
    echo "injecting SIGTERM at restore point: $point" >&2
    kill -TERM "$$"
  fi
  if [[ "$test_fail_point" == "$point" ]]; then
    echo "injecting failure at restore point: $point" >&2
    return 1
  fi
}
inject_at after-database-switch

moved_count=0
old_move_count=0
while IFS=$'\t' read -r object_id object_size object_digest; do
  [[ -n "$object_id" ]] || continue
  journal_append old-intent "$object_id" "$object_size" "$object_digest"
  mv -- "$resolved_upload/$object_id" "$cutover_old/$object_id"
  fsync_path "$resolved_upload"
  fsync_path "$cutover_old"
  journal_append old-done "$object_id" "$object_size" "$object_digest"
  moved_count=$((moved_count + 1))
  old_move_count=$((old_move_count + 1))
  if (( test_fail_after_moves > 0 && moved_count >= test_fail_after_moves )); then
    echo "injecting the requested upload activation failure" >&2
    exit 1
  fi
  if (( old_move_count == 1 )); then
    inject_at after-first-old
  fi
done <"$old_manifest"

new_move_count=0
while IFS=$'\t' read -r object_id object_size object_digest; do
  [[ -n "$object_id" ]] || continue
  journal_append new-intent "$object_id" "$object_size" "$object_digest"
  mv -- "$cutover_new/$object_id" "$resolved_upload/$object_id"
  fsync_path "$resolved_upload"
  fsync_path "$cutover_new"
  journal_append new-done "$object_id" "$object_size" "$object_digest"
  moved_count=$((moved_count + 1))
  new_move_count=$((new_move_count + 1))
  if (( test_fail_after_moves > 0 && moved_count >= test_fail_after_moves )); then
    echo "injecting the requested upload activation failure" >&2
    exit 1
  fi
  if (( new_move_count == 1 )); then
    inject_at after-first-new
  fi
done <"$new_manifest"

validate_upload_namespace "$resolved_upload" true "$cutover_dir" \
  || { echo "post-activation upload namespace is invalid" >&2; exit 1; }
verify_manifest_objects "$new_manifest" "$resolved_upload" "${cutover_dir##*/}" \
  || { echo "post-activation upload object set differs from the validated backup" >&2; exit 1; }
current_rows="$work_dir/current-upload-rows.tsv"
query_current_upload_rows "$current_rows"
validate_upload_rows_file "$current_rows" "$resolved_upload" \
  || { echo "post-activation database/upload integrity failed" >&2; exit 1; }

# Old objects remain on the upload filesystem until a complete, verified copy
# exists in rollback retention. This avoids cross-filesystem mv semantics and
# keeps the atomic compensation source alive through the safety boundary.
while IFS=$'\t' read -r object_id object_size object_digest; do
  [[ -n "$object_id" ]] || continue
  cp -- "$cutover_old/$object_id" "$previous_uploads/$object_id"
  chmod 0600 "$previous_uploads/$object_id"
  chown --reference="$resolved_rollback" "$previous_uploads/$object_id"
  object_matches "$previous_uploads/$object_id" "$object_size" "$object_digest" \
    || { echo "rollback-retention copy verification failed: $object_id" >&2; exit 1; }
  fsync_path "$previous_uploads/$object_id"
done <"$old_manifest"
fsync_path "$previous_uploads"
verify_manifest_objects "$old_manifest" "$previous_uploads"
journal_append rollback-uploads-verified
inject_at before-commit

journal_append commit-intent
# Ignore interactive signals only across the tiny replay-floor commit boundary.
# Once the durable floor succeeds, the new data plane is authoritative even if
# later connection re-enable or cleanup fails.
trap '' INT TERM
if [[ -n "$rollback_state_file" ]]; then
  commit_args=()
  [[ "$allow_generation_change" == true ]] && commit_args+=(--allow-generation-change)
  python3 "$script_dir/backup-security.py" commit-restore-state \
    "$payload_dir/manifest.txt" "$rollback_state_file" "${commit_args[@]}"
fi
restore_committed=true
journal_append committed || preserve_work=true
trap 'exit 130' INT
trap 'exit 143' TERM

# Clearing the catalog marker happens only after the replay floor made the new
# data plane authoritative.  A failure here is operationally fatal and leaves
# evidence for the next run, but must never roll back the committed restore.
restore_outcome_clear_started=true
clear_restore_outcome "$incoming_outcome_marker"
restore_outcome_cleared=true
release_database_fence
close_db_sessions
if [[ "$preserve_work" != true ]]; then
  remove_cutover_dir
  remove_work_dir
else
  echo "restore committed, but journal cleanup was retained for operator inspection: $cutover_dir" >&2
fi
compensation_required=false
trap - ERR EXIT INT TERM

echo "restore complete: database and $resolved_upload"
echo "previous upload files retained at: $previous_uploads"
echo "pre-restore database retained at: $rollback_dump"
