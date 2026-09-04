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
for command in awk bash chown chmod cmp cp createdb date du find flock grep id initdb mkfifo mktemp mv \
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
control_session_pid=""
control_session_in=""
control_session_out=""
target_coordinator_pid=""
target_coordinator_in=""
target_coordinator_out=""
primary_worker_pid=""
primary_worker_in=""
primary_worker_out=""
compensation_worker_pid=""
compensation_worker_in=""
compensation_worker_out=""
declare -A psql_session_state=()
declare -A psql_session_pid_registry=()
declare -A psql_session_input_fd_registry=()
declare -A psql_session_output_fd_registry=()
declare -A psql_session_input_anchor_fd_registry=()
declare -A psql_session_output_anchor_fd_registry=()
declare -A psql_session_fifo_dir_registry=()
declare -A psql_session_input_fifo_registry=()
declare -A psql_session_output_fifo_registry=()
target_database=""
control_backend_pid=""
target_coordinator_backend_pid=""
primary_backend_pid=""
compensation_backend_pid=""
last_restore_transaction_label=""
last_restore_transaction_kind=""
last_restore_transaction_xid=""
last_restore_transaction_status=""
incoming_restore_xid=""
incoming_restore_status="not-started"
rollback_restore_xid=""
rollback_restore_status="not-started"
replacement_committed=false
database_outcome_unknown=false
restore_transaction_active=false
active_restore_kind=""
active_restore_barrier_key=""
active_restore_barrier_label=""
active_restore_worker=""
active_restore_xid=""
active_restore_destructive_sent=false
fence_attempted=false
database_fence_active=false
database_generation_state="original"
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
  if ! python3 - "$journal_file" "$@" <<'PY'
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
    remaining = memoryview(line)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError("restore journal write made no progress")
        remaining = remaining[written:]
    os.fsync(fd)
finally:
    os.close(fd)
PY
  then
    return 1
  fi
  fsync_path "$cutover_dir" || return 1
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

# Bash deliberately tracks only one active coprocess. A restore needs four
# independently supervised PostgreSQL sessions at the same time, so each
# session is represented by an explicit lifecycle record plus two private
# FIFOs. The record is authoritative from before namespace creation until the
# child has been reaped and every parent FD has been closed. This lets EXIT
# cleanup recover a signal at any startup boundary without guessing from a
# caller-owned "started" flag.
psql_session_label_is_valid() {
  [[ "$1" =~ ^(control|coordinator|primary|compensation)$ ]]
}

sync_psql_session_scalars() {
  local label="$1"
  local session_pid="${psql_session_pid_registry[$label]:-}"
  local session_input="${psql_session_input_fd_registry[$label]:-}"
  local session_output="${psql_session_output_fd_registry[$label]:-}"
  case "$label" in
    control)
      control_session_pid="$session_pid"
      control_session_in="$session_input"
      control_session_out="$session_output"
      ;;
    coordinator)
      target_coordinator_pid="$session_pid"
      target_coordinator_in="$session_input"
      target_coordinator_out="$session_output"
      ;;
    primary)
      primary_worker_pid="$session_pid"
      primary_worker_in="$session_input"
      primary_worker_out="$session_output"
      ;;
    compensation)
      compensation_worker_pid="$session_pid"
      compensation_worker_in="$session_input"
      compensation_worker_out="$session_output"
      ;;
    *) return 2 ;;
  esac
}

forget_psql_session_pid() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_pid_registry[$label]"
  sync_psql_session_scalars "$label"
}

forget_psql_session_input_fd() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_input_fd_registry[$label]"
  sync_psql_session_scalars "$label"
}

forget_psql_session_output_fd() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_output_fd_registry[$label]"
  sync_psql_session_scalars "$label"
}

forget_psql_session_input_anchor_fd() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_input_anchor_fd_registry[$label]"
}

forget_psql_session_output_anchor_fd() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_output_anchor_fd_registry[$label]"
}

clear_psql_session_registration() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  unset "psql_session_state[$label]"
  unset "psql_session_pid_registry[$label]"
  unset "psql_session_input_fd_registry[$label]"
  unset "psql_session_output_fd_registry[$label]"
  unset "psql_session_input_anchor_fd_registry[$label]"
  unset "psql_session_output_anchor_fd_registry[$label]"
  unset "psql_session_fifo_dir_registry[$label]"
  unset "psql_session_input_fifo_registry[$label]"
  unset "psql_session_output_fifo_registry[$label]"
  sync_psql_session_scalars "$label"
}

psql_fd_is_open() {
  local fd="${1:-}"
  [[ "$fd" =~ ^[0-9]+$ ]] && (( fd >= 3 )) \
    && [[ -e "/proc/$BASHPID/fd/$fd" ]]
}

close_psql_fd_if_open() {
  local fd="${1:-}"
  if psql_fd_is_open "$fd"; then
    exec {fd}>&-
  fi
}

# Child processes must shed every parent-owned session endpoint. Use BASHPID,
# not $$, because $$ continues to identify the parent shell inside a subshell.
# Checking each descriptor first also makes the operation safe when two cleanup
# phases observe an already-closed FD.
close_inherited_parent_fds() {
  local inherited_fd anchor_label close_ok=true
  for inherited_fd in "$rollback_state_lock_fd" \
    "$control_session_in" "$control_session_out" \
    "$target_coordinator_in" "$target_coordinator_out" \
    "$primary_worker_in" "$primary_worker_out" \
    "$compensation_worker_in" "$compensation_worker_out"; do
    if psql_fd_is_open "$inherited_fd" \
       && ! close_psql_fd_if_open "$inherited_fd"; then
      close_ok=false
    fi
  done
  for anchor_label in control coordinator primary compensation; do
    for inherited_fd in \
      "${psql_session_input_anchor_fd_registry[$anchor_label]:-}" \
      "${psql_session_output_anchor_fd_registry[$anchor_label]:-}"; do
      if psql_fd_is_open "$inherited_fd" \
         && ! close_psql_fd_if_open "$inherited_fd"; then
        close_ok=false
      fi
    done
  done
  [[ "$close_ok" == true ]]
}

close_psql_session_anchors() {
  local label="$1" input_anchor output_anchor close_ok=true
  psql_session_label_is_valid "$label" || return 2
  input_anchor="${psql_session_input_anchor_fd_registry[$label]:-}"
  output_anchor="${psql_session_output_anchor_fd_registry[$label]:-}"
  if [[ -n "$input_anchor" ]]; then
    if close_psql_fd_if_open "$input_anchor"; then
      forget_psql_session_input_anchor_fd "$label" || close_ok=false
    else
      close_ok=false
    fi
  fi
  if [[ -n "$output_anchor" ]]; then
    if close_psql_fd_if_open "$output_anchor"; then
      forget_psql_session_output_anchor_fd "$label" || close_ok=false
    else
      close_ok=false
    fi
  fi
  [[ "$close_ok" == true ]]
}

psql_session_anchors_are_closed() {
  local label="$1"
  psql_session_label_is_valid "$label" || return 2
  [[ -z "${psql_session_input_anchor_fd_registry[$label]:-}" \
     && -z "${psql_session_output_anchor_fd_registry[$label]:-}" ]]
}

remove_psql_session_namespace() {
  local label="$1" fifo_path fifo_dir
  local namespace_ok=true
  psql_session_label_is_valid "$label" || return 2
  for fifo_path in "${psql_session_input_fifo_registry[$label]:-}" \
    "${psql_session_output_fifo_registry[$label]:-}"; do
    [[ -n "$fifo_path" ]] || continue
    if [[ -p "$fifo_path" && ! -L "$fifo_path" ]]; then
      rm -- "$fifo_path" || namespace_ok=false
    elif [[ -e "$fifo_path" || -L "$fifo_path" ]]; then
      echo "refusing to remove unexpected psql session endpoint: $fifo_path" >&2
      namespace_ok=false
    fi
  done
  fifo_dir="${psql_session_fifo_dir_registry[$label]:-}"
  if [[ -n "$fifo_dir" ]]; then
    if [[ -d "$fifo_dir" && ! -L "$fifo_dir" ]]; then
      rmdir -- "$fifo_dir" || namespace_ok=false
    elif [[ -e "$fifo_dir" || -L "$fifo_dir" ]]; then
      echo "refusing to remove unexpected psql session namespace: $fifo_dir" >&2
      namespace_ok=false
    fi
  fi
  if [[ "$namespace_ok" == true ]]; then
    unset "psql_session_fifo_dir_registry[$label]"
    unset "psql_session_input_fifo_registry[$label]"
    unset "psql_session_output_fifo_registry[$label]"
  fi
  [[ "$namespace_ok" == true ]]
}

drain_psql_output_fd() {
  local output_fd="$1" output_file="${2:-}" line
  local output_ok=true
  psql_fd_is_open "$output_fd" || return 1
  while IFS= read -r line <&"$output_fd"; do
    if [[ -n "$output_file" ]] \
       && ! printf '%s\n' "$line" >>"$output_file"; then
      # Continue draining even if diagnostics cannot be persisted. Otherwise a
      # full stdout pipe could prevent the exact child from exiting and being
      # reaped.
      output_ok=false
      output_file=""
    fi
  done
  [[ "$output_ok" == true ]]
}

dispose_starting_psql_session() {
  local label="$1"
  local session_pid session_input session_output output_file
  local input_open=false output_open=false anchors_closed=true cleanup_ok=true
  psql_session_label_is_valid "$label" || return 2
  session_pid="${psql_session_pid_registry[$label]:-}"
  session_input="${psql_session_input_fd_registry[$label]:-}"
  session_output="${psql_session_output_fd_registry[$label]:-}"
  output_file="$work_dir/psql-session-$label-startup.out"
  psql_fd_is_open "$session_input" && input_open=true
  psql_fd_is_open "$session_output" && output_open=true
  if ! close_psql_session_anchors "$label"; then
    anchors_closed=false
    cleanup_ok=false
  fi

  if [[ "$input_open" == true && "$output_open" == true \
     && "$anchors_closed" == true ]]; then
    # Both real endpoints completed and every startup anchor is gone, so psql
    # can exit cleanly on stdin EOF. Keep stdout open until EOF and reap the
    # exact child before releasing that FD.
    if ! close_psql_fd_if_open "$session_input"; then
      cleanup_ok=false
      [[ "$session_pid" =~ ^[0-9]+$ ]] && kill -TERM "$session_pid" 2>/dev/null || true
    fi
    forget_psql_session_input_fd "$label" || cleanup_ok=false
    drain_psql_output_fd "$session_output" "$output_file" || cleanup_ok=false
    if [[ "$session_pid" =~ ^[0-9]+$ ]]; then
      wait "$session_pid" 2>/dev/null || true
      forget_psql_session_pid "$label" || cleanup_ok=false
    else
      cleanup_ok=false
    fi
    close_psql_fd_if_open "$session_output" || cleanup_ok=false
    forget_psql_session_output_fd "$label" || cleanup_ok=false
  else
    # An incomplete startup (including an anchor-close failure) is never
    # allowed to drain: an inherited writer could suppress EOF. Terminate the
    # exact child first, then close every partial endpoint and reap it.
    if [[ "$session_pid" =~ ^[0-9]+$ ]]; then
      kill -TERM "$session_pid" 2>/dev/null || true
    fi
    close_psql_fd_if_open "$session_input" || cleanup_ok=false
    forget_psql_session_input_fd "$label" || cleanup_ok=false
    close_psql_fd_if_open "$session_output" || cleanup_ok=false
    forget_psql_session_output_fd "$label" || cleanup_ok=false
    if [[ "$session_pid" =~ ^[0-9]+$ ]]; then
      wait "$session_pid" 2>/dev/null || true
      forget_psql_session_pid "$label" || cleanup_ok=false
    fi
    close_psql_session_anchors "$label" || cleanup_ok=false
  fi
  remove_psql_session_namespace "$label" || cleanup_ok=false
  clear_psql_session_registration "$label" || cleanup_ok=false
  [[ "$cleanup_ok" == true ]]
}

start_psql_session() {
  local label="$1" pid_variable="$2" input_variable="$3" output_variable="$4"
  local connection_scope="$5"
  local fifo_dir="$work_dir/psql-session-$label"
  local input_fifo="$fifo_dir/input" output_fifo="$fifo_dir/output"
  local input_anchor="" output_anchor=""
  local session_input="" session_output="" child_pid=""
  local deferred_start_signal=""
  local -a psql_connection_arguments=()

  psql_session_label_is_valid "$label" || return 2
  case "$label:$pid_variable:$input_variable:$output_variable:$connection_scope" in
    control:control_session_pid:control_session_in:control_session_out:maintenance|\
    coordinator:target_coordinator_pid:target_coordinator_in:target_coordinator_out:target|\
    primary:primary_worker_pid:primary_worker_in:primary_worker_out:target|\
    compensation:compensation_worker_pid:compensation_worker_in:compensation_worker_out:target) ;;
    *) return 2 ;;
  esac
  [[ "${psql_session_state[$label]:-closed}" == closed ]] || return 2

  # PostgreSQL rejects ALTER DATABASE ... ALLOW_CONNECTIONS when it is issued
  # from the database being fenced. Keep the bounded control backend in the
  # standard maintenance database; replacement workers continue to inherit the
  # target database from the authenticated DATABASE_URL.
  if [[ "$connection_scope" == maintenance ]]; then
    psql_connection_arguments=(--dbname=postgres)
  fi

  psql_session_state[$label]=preparing
  psql_session_fifo_dir_registry[$label]="$fifo_dir"
  psql_session_input_fifo_registry[$label]="$input_fifo"
  psql_session_output_fifo_registry[$label]="$output_fifo"
  if ! mkdir -m 0700 -- "$fifo_dir"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  if ! mkfifo -m 0600 -- "$input_fifo" "$output_fifo"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi

  # Temporary O_RDWR anchors make every subsequent single-direction FIFO open
  # nonblocking even if the child exits between its two redirections. They are
  # globally registered before spawn so signal cleanup can always find them.
  if ! exec {input_anchor}<>"$input_fifo"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  psql_session_input_anchor_fd_registry[$label]="$input_anchor"
  if ! exec {output_anchor}<>"$output_fifo"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  psql_session_output_anchor_fd_registry[$label]="$output_anchor"

  # An asynchronous signal may otherwise arrive after Bash has spawned the
  # child but before $! is copied into the registry. Defer only INT/TERM across
  # that tiny boundary. Caught traps are reset in the child execution
  # environment, and the child explicitly restores defaults once its FIFO
  # redirections have rendezvoused, so it always remains terminable.
  trap 'deferred_start_signal=INT' INT
  trap 'deferred_start_signal=TERM' TERM
  (
    trap - INT TERM
    # The redirections have already duplicated this session's FIFOs onto stdin
    # and stdout. Closing inherited dynamic FDs cannot close those descriptors.
    close_inherited_parent_fds || exit 125
    exec "${pg_client[@]}" psql "${psql_connection_arguments[@]}" \
      --no-psqlrc --quiet --tuples-only --no-align \
      --set ON_ERROR_STOP=1
  ) <"$input_fifo" >"$output_fifo" &
  child_pid=$!
  psql_session_pid_registry[$label]="$child_pid"
  psql_session_state[$label]=starting
  sync_psql_session_scalars "$label"
  # start_psql_session is invoked only after the script-level signal handlers
  # below are installed. Restore those exact handlers without command
  # substitution: a subshell used for $(trap -p) may observe reset trap state.
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [[ -n "$deferred_start_signal" ]]; then
    # Replay the exact signal only after cleanup can see the child PID, FIFO
    # namespace and lifecycle state. The restored script trap performs the
    # normal status-preserving EXIT cleanup.
    kill -s "$deferred_start_signal" "$BASHPID"
    case "$deferred_start_signal" in
      INT) return 130 ;;
      TERM) return 143 ;;
    esac
  fi

  # Anchors make these directional opens independent of child scheduling.
  if ! exec {session_input}>"$input_fifo"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  psql_session_input_fd_registry[$label]="$session_input"
  sync_psql_session_scalars "$label"
  if ! exec {session_output}<"$output_fifo"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  psql_session_output_fd_registry[$label]="$session_output"
  sync_psql_session_scalars "$label"

  # Normal operation must retain only the directional endpoints. Closing and
  # unregistering both anchors restores unambiguous EOF/SIGPIPE semantics.
  if ! close_psql_session_anchors "$label" \
     || ! psql_session_anchors_are_closed "$label"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi

  if ! remove_psql_session_namespace "$label"; then
    dispose_starting_psql_session "$label" || true
    return 1
  fi
  psql_session_state[$label]=open
}

# A pg_restore producer retains only stdout already duplicated to its selected
# worker. Inherited session writers would otherwise suppress EOF and leave
# cleanup waiting forever for a transaction rollback.
run_pg_client_without_parent_fds() (
  close_inherited_parent_fds || exit 125
  exec "${pg_client[@]}" "$@"
)

close_psql_session() {
  local label="$1" output_file="${2:-$work_dir/psql-session-$label-close.out}"
  local session_pid session_input session_output session_status=0
  local close_ok=true prior_state
  psql_session_label_is_valid "$label" || return 2
  prior_state="${psql_session_state[$label]:-closed}"
  case "$prior_state" in
    closed) clear_psql_session_registration "$label"; return 0 ;;
    preparing|starting) dispose_starting_psql_session "$label"; return ;;
    open)
      psql_session_state[$label]=closing
      : >"$output_file" || { close_ok=false; output_file=""; }
      ;;
    closing) ;;
    *) echo "invalid psql session lifecycle state: $label" >&2; return 2 ;;
  esac
  session_pid="${psql_session_pid_registry[$label]:-}"
  session_input="${psql_session_input_fd_registry[$label]:-}"
  session_output="${psql_session_output_fd_registry[$label]:-}"

  # EOF is psql's graceful shutdown protocol. Preserve the read endpoint while
  # draining and waiting; closing it first can SIGPIPE the child and erase the
  # real exit status.
  if [[ -n "$session_input" ]]; then
    if ! psql_fd_is_open "$session_input" \
       || ! close_psql_fd_if_open "$session_input"; then
      close_ok=false
      [[ "$session_pid" =~ ^[0-9]+$ ]] && kill -TERM "$session_pid" 2>/dev/null || true
    fi
    forget_psql_session_input_fd "$label" || close_ok=false
  elif [[ "$prior_state" == open ]]; then
    close_ok=false
    [[ "$session_pid" =~ ^[0-9]+$ ]] && kill -TERM "$session_pid" 2>/dev/null || true
  fi
  if [[ -n "$session_output" ]] \
     && ! drain_psql_output_fd "$session_output" "$output_file"; then
    close_ok=false
  elif [[ -z "$session_output" ]]; then
    close_ok=false
  fi
  if [[ "$session_pid" =~ ^[0-9]+$ ]]; then
    if wait "$session_pid" 2>/dev/null; then
      session_status=0
    else
      session_status=$?
      close_ok=false
    fi
    forget_psql_session_pid "$label" || close_ok=false
  else
    close_ok=false
  fi
  if [[ -n "$session_output" ]]; then
    close_psql_fd_if_open "$session_output" || close_ok=false
    forget_psql_session_output_fd "$label" || close_ok=false
  fi
  remove_psql_session_namespace "$label" || close_ok=false
  clear_psql_session_registration "$label" || close_ok=false
  if [[ "$close_ok" != true ]]; then
    echo "psql session did not close cleanly: $label (status=$session_status)" >&2
    return 1
  fi
}

close_db_sessions() {
  local label close_ok=true
  # Close workers first and the advisory-lock owner last. Continue after one
  # failure so every exact PID/FD registration is consumed and cleared.
  for label in primary compensation coordinator control; do
    case "${psql_session_state[$label]:-closed}" in
      closed) ;;
      preparing|starting|open|closing)
        if ! close_psql_session "$label"; then
          close_ok=false
        fi
        ;;
      *)
        echo "invalid psql session lifecycle state: $label" >&2
        # Registry corruption must not turn into descriptor erasure without
        # process cleanup. Dispose every recorded resource fail-closed.
        dispose_starting_psql_session "$label" || true
        close_ok=false
        ;;
    esac
  done
  [[ "$close_ok" == true ]]
}

abort_psql_session_for_cleanup() {
  local label="$1" output_file="$2"
  local session_pid session_input session_output cleanup_ok=true
  psql_session_label_is_valid "$label" || return 2
  [[ "${psql_session_state[$label]:-closed}" == open ]] || return 1
  psql_session_state[$label]=closing
  session_pid="${psql_session_pid_registry[$label]:-}"
  session_input="${psql_session_input_fd_registry[$label]:-}"
  session_output="${psql_session_output_fd_registry[$label]:-}"
  # Closing stdin is the transaction-safe interrupt. psql either finishes an
  # already-buffered COMMIT or disconnects so PostgreSQL rolls back an open
  # transaction. Drain stdout, reap the exact PID, then close stdout; the
  # catalog barrier determines which database outcome actually committed.
  if ! psql_fd_is_open "$session_input" \
     || ! close_psql_fd_if_open "$session_input"; then
    cleanup_ok=false
    [[ "$session_pid" =~ ^[0-9]+$ ]] && kill -TERM "$session_pid" 2>/dev/null || true
  fi
  forget_psql_session_input_fd "$label" || cleanup_ok=false
  drain_psql_output_fd "$session_output" "$output_file" || cleanup_ok=false
  if [[ "$session_pid" =~ ^[0-9]+$ ]]; then
    wait "$session_pid" 2>/dev/null || true
    forget_psql_session_pid "$label" || cleanup_ok=false
  else
    cleanup_ok=false
  fi
  close_psql_fd_if_open "$session_output" || cleanup_ok=false
  forget_psql_session_output_fd "$label" || cleanup_ok=false
  remove_psql_session_namespace "$label" || cleanup_ok=false
  clear_psql_session_registration "$label" || cleanup_ok=false
  [[ "$cleanup_ok" == true ]]
}

abort_active_restore_worker_for_cleanup() {
  local output_file="$work_dir/replace-$active_restore_barrier_label.out"
  case "$active_restore_worker" in
    primary|compensation)
      if [[ "${psql_session_state[$active_restore_worker]:-closed}" != open ]]; then
        echo "active restore worker is not available for exact cleanup" >&2
        return 1
      fi
      abort_psql_session_for_cleanup "$active_restore_worker" "$output_file"
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

control_session_command() {
  psql_session_command "$control_session_in" "$control_session_out" "$1" "$2"
}

target_coordinator_command() {
  psql_session_command "$target_coordinator_in" "$target_coordinator_out" "$1" "$2"
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

wait_for_restore_transaction_barrier() {
  local barrier_key="$1" label="$2" transaction_kind="$3" transaction_xid="$4"
  local barrier_sql="$work_dir/$label-transaction-barrier.sql"
  local barrier_output="$work_dir/$label-transaction-barrier.out"
  local status_prefix status_line status_count
  [[ "$barrier_key" =~ ^northstar-restore-[0-9a-f]{32}-(incoming|rollback)$ \
     && "$label" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || return 2
  case "$transaction_kind" in
    incoming|rollback) ;;
    *) return 2 ;;
  esac
  [[ "$barrier_key" == "northstar-restore-$restore_id-$transaction_kind" ]] || return 2
  [[ -z "$transaction_xid" || "$transaction_xid" =~ ^[1-9][0-9]{0,19}$ ]] || return 2
  status_prefix="__NORTHSTAR_RESTORE_XACT_STATUS_${transaction_kind}_${restore_id}__"
  {
    printf '\\set restore_barrier_key %s\n' "$barrier_key"
    if [[ -n "$transaction_xid" ]]; then
      printf '\\set restore_xid %s\n' "$transaction_xid"
    fi
    printf '%s\n' 'BEGIN;'
    printf "%s\n" \
      "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0));"
    if [[ -n "$transaction_xid" ]]; then
      printf "SELECT '%s' || COALESCE(pg_catalog.pg_xact_status((:'restore_xid')::pg_catalog.xid8), '__TOO_OLD__);\n" \
        "$status_prefix"
    fi
    printf '%s\n' 'COMMIT;'
  } >"$barrier_sql" || return 1
  target_coordinator_command "$barrier_sql" "$barrier_output" || {
    database_outcome_unknown=true
    echo "cannot establish that the $label replacement transaction has ended" >&2
    return 1
  }
  if [[ -z "$transaction_xid" ]]; then
    return 0
  fi
  status_line="$(sed -n "s/^${status_prefix}//p" "$barrier_output")"
  status_count="$(awk -v prefix="$status_prefix" \
    'index($0, prefix) == 1 { count += 1 } END { print count + 0 }' "$barrier_output")"
  last_restore_transaction_label="$label"
  last_restore_transaction_kind="$transaction_kind"
  last_restore_transaction_xid="$transaction_xid"
  last_restore_transaction_status="$status_line"
  if [[ -z "$status_line" || "$status_count" != 1 ]]; then
    database_outcome_unknown=true
    last_restore_transaction_status="__INVALID__"
    echo "$label replacement transaction status query returned an ambiguous result" >&2
    return 2
  fi
  case "$last_restore_transaction_status" in
    committed|aborted) return 0 ;;
    'in progress'|__TOO_OLD__)
      database_outcome_unknown=true
      echo "$label replacement transaction has no final retained PostgreSQL status" >&2
      return 2
      ;;
    *)
      database_outcome_unknown=true
      echo "PostgreSQL returned an unrecognized replacement transaction status" >&2
      return 2
      ;;
  esac
}

record_restore_transaction_result() {
  local transaction_kind="$1" label="$2" transaction_xid="$3" transaction_status="$4"
  [[ "$label" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || return 2
  [[ -z "$transaction_xid" || "$transaction_xid" =~ ^[1-9][0-9]{0,19}$ ]] || return 2
  [[ "$transaction_status" == committed || "$transaction_status" == aborted ]] || return 2
  [[ "$transaction_status" != committed || -n "$transaction_xid" ]] || return 2
  case "$transaction_kind" in
    incoming)
      [[ "$label" == restored && "$incoming_restore_status" == active ]] || return 2
      incoming_restore_xid="$transaction_xid"
      incoming_restore_status="$transaction_status"
      if [[ "$transaction_status" == committed ]]; then
        database_generation_state="replacement"
      else
        database_generation_state="original"
      fi
      ;;
    rollback)
      [[ "$label" == rollback \
         && "$rollback_restore_status" == active \
         && "$incoming_restore_status" == committed \
         && ( -z "$transaction_xid" || "$transaction_xid" != "$incoming_restore_xid" ) ]] \
        || return 2
      rollback_restore_xid="$transaction_xid"
      rollback_restore_status="$transaction_status"
      if [[ "$transaction_status" == committed ]]; then
        database_generation_state="original"
      else
        database_generation_state="replacement"
      fi
      ;;
    *) return 2 ;;
  esac
  last_restore_transaction_label="$label"
  last_restore_transaction_kind="$transaction_kind"
  last_restore_transaction_xid="$transaction_xid"
  last_restore_transaction_status="$transaction_status"
  replacement_committed=false
  [[ "$transaction_status" != committed ]] || replacement_committed=true
}

settle_active_restore_transaction() {
  local settled_kind settled_label settled_xid destructive_sent settled_status
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
    # transaction waiting for stdin while the target coordinator waits forever
    # on its transaction lock.
    if ! abort_active_restore_worker_for_cleanup; then
      database_outcome_unknown=true
      return 1
    fi
  fi
  settled_kind="$active_restore_kind"
  settled_label="$active_restore_barrier_label"
  settled_xid="$active_restore_xid"
  destructive_sent="$active_restore_destructive_sent"
  if ! wait_for_restore_transaction_barrier "$active_restore_barrier_key" \
      "$settled_label" "$settled_kind" "$settled_xid"; then
    database_outcome_unknown=true
    return 1
  fi
  if [[ -z "$settled_xid" ]]; then
    if [[ "$destructive_sent" == true ]]; then
      database_outcome_unknown=true
      echo "$settled_label replacement reached destructive SQL without a recorded transaction ID" >&2
      return 1
    fi
    # READY gates every destructive byte. If no XID was captured, the barrier
    # proves only the harmless header transaction ended; the database is
    # unchanged even when the worker acknowledgement was lost.
    settled_status=aborted
  else
    settled_status="$last_restore_transaction_status"
  fi
  if ! record_restore_transaction_result "$settled_kind" "$settled_label" \
      "$settled_xid" "$settled_status"; then
    database_outcome_unknown=true
    echo "invalid $settled_kind replacement transaction state transition" >&2
    return 1
  fi
  restore_transaction_active=false
  active_restore_kind=""
  active_restore_barrier_key=""
  active_restore_barrier_label=""
  active_restore_worker=""
  active_restore_xid=""
  active_restore_destructive_sent=false
  if ! journal_append database-transaction-outcome "$settled_kind" "$settled_label" \
      "${settled_xid:-unassigned}" "$settled_status"; then
    database_outcome_unknown=true
    echo "could not persist the $settled_label replacement outcome in the recovery journal" >&2
    return 1
  fi
}

read_restore_worker_identity() {
  local label="$1" session_in="$2" session_out="$3" output_file="$4"
  local -n pid_result="$5" database_result="$6"
  local init_sql="$work_dir/$label-worker-init.sql" parsed_database parsed_pid
  cat >"$init_sql" <<SQL
SET application_name TO 'northstar-restore-$restore_id-$label';
SELECT '__DATABASE__' || current_database();
SELECT '__BACKEND_PID__' || pg_backend_pid()::text;
SQL
  psql_session_command "$session_in" "$session_out" "$init_sql" "$output_file" || return 1
  parsed_database="$(sed -n 's/^__DATABASE__//p' "$output_file")"
  parsed_pid="$(sed -n 's/^__BACKEND_PID__//p' "$output_file")"
  [[ "$parsed_pid" =~ ^[0-9]+$ ]] \
    || { echo "$label restore worker has an unsafe backend identity" >&2; return 1; }
  pid_result="$parsed_pid"
  database_result="$parsed_database"
}

discover_target_coordinator_identity() {
  local worker_database
  read_restore_worker_identity coordinator "$target_coordinator_in" \
    "$target_coordinator_out" "$work_dir/target-coordinator-init.out" \
    target_coordinator_backend_pid worker_database || return 1
  [[ "$worker_database" =~ ^[A-Za-z0-9_.-]{1,63}$ \
     && "$worker_database" != postgres \
     && "$worker_database" != template0 \
     && "$worker_database" != template1 ]] \
    || { echo "restore coordinator has an unsafe target database identity" >&2; return 1; }
  target_database="$worker_database"
}

verify_primary_target_identity() {
  local worker_database
  read_restore_worker_identity primary "$primary_worker_in" "$primary_worker_out" \
    "$work_dir/primary-worker-init.out" primary_backend_pid worker_database || return 1
  [[ -n "$target_database" && "$worker_database" == "$target_database" ]] \
    || { echo "primary restore worker is not connected to the target database" >&2; return 1; }
}

verify_compensation_target_identity() {
  local worker_database
  read_restore_worker_identity compensation "$compensation_worker_in" \
    "$compensation_worker_out" "$work_dir/compensation-worker-init.out" \
    compensation_backend_pid worker_database || return 1
  [[ -n "$target_database" && "$worker_database" == "$target_database" ]] \
    || { echo "compensation restore worker is not connected to the target database" >&2; return 1; }
}

acquire_target_coordination_locks() {
  local lock_sql="$work_dir/target-coordinator-locks.sql"
  local lock_output="$work_dir/target-coordinator-locks.out"
  cat >"$lock_sql" <<SQL
SET application_name TO 'northstar-restore-$restore_id-coordinator';
SELECT CASE WHEN pg_try_advisory_lock($maintenance_lock_key)
       THEN '__MAINTENANCE_LOCK_OK__' ELSE '__MAINTENANCE_LOCK_BUSY__' END;
SQL
  target_coordinator_command "$lock_sql" "$lock_output" || return 1
  grep -qx '__MAINTENANCE_LOCK_OK__' "$lock_output" \
    || { echo "another backup or restore holds the target database maintenance fence" >&2; return 1; }
}

verify_restore_transaction_status_capability() {
  local probe_sql="$work_dir/restore-transaction-status-probe.sql"
  local probe_output="$work_dir/restore-transaction-status-probe.out"
  cat >"$probe_sql" <<'SQL'
BEGIN;
SELECT pg_catalog.pg_current_xact_id()::text AS northstar_probe_xid \gset
ROLLBACK;
SELECT '__RESTORE_XACT_PROBE__' ||
       COALESCE(
         pg_catalog.pg_xact_status((:'northstar_probe_xid')::pg_catalog.xid8),
         '__TOO_OLD__'
       );
SQL
  target_coordinator_command "$probe_sql" "$probe_output" || return 1
  grep -qx '__RESTORE_XACT_PROBE__aborted' "$probe_output" || {
    echo "restore requires working pg_current_xact_id()/pg_xact_status(xid8) support" >&2
    return 1
  }
}

acquire_primary_policy_lock() {
  local lock_sql="$work_dir/primary-policy-lock.sql"
  local lock_output="$work_dir/primary-policy-lock.out"
  cat >"$lock_sql" <<'SQL'
SELECT CASE WHEN pg_try_advisory_lock(
                   pg_catalog.hashtextextended(
                     'northstar-database-role-policy-v1',0
                   )
                 )
       THEN '__POLICY_LOCK_OK__' ELSE '__POLICY_LOCK_BUSY__' END;
SQL
  primary_worker_command "$lock_sql" "$lock_output" || return 1
  grep -qx '__POLICY_LOCK_OK__' "$lock_output" \
    || { echo "a migration or database-grant reconciliation holds the target database policy fence" >&2; return 1; }
}

release_primary_policy_lock_after_fence() {
  local unlock_sql="$work_dir/primary-policy-unlock.sql"
  local unlock_output="$work_dir/primary-policy-unlock.out"
  [[ "$database_fence_active" == true ]] \
    || { echo "refusing to release the policy lock before the target connection fence" >&2; return 1; }
  cat >"$unlock_sql" <<'SQL'
SELECT CASE WHEN pg_advisory_unlock(
                   pg_catalog.hashtextextended(
                     'northstar-database-role-policy-v1',0
                   )
                 )
       THEN '__POLICY_UNLOCK_OK__' ELSE '__POLICY_UNLOCK_MISSING__' END;
SQL
  primary_worker_command "$unlock_sql" "$unlock_output" || return 1
  grep -qx '__POLICY_UNLOCK_OK__' "$unlock_output" \
    || { echo "primary restore worker did not own the database policy fence" >&2; return 1; }
}

establish_restore_database_authorities() {
  local init_sql="$work_dir/db-session-init.sql" init_output="$work_dir/db-session-init.out"
  local grant_check_sql="$work_dir/grant-boundary-check.sql"
  local grant_check_output="$work_dir/grant-boundary-check.out"
  local control_database
  start_psql_session control control_session_pid control_session_in control_session_out maintenance
  cat >"$init_sql" <<SQL
SET application_name TO 'northstar-restore-$restore_id';
SET search_path TO pg_catalog,pg_temp;
SELECT '__DATABASE__' || current_database();
SELECT '__BACKEND_PID__' || pg_backend_pid()::text;
SQL
  control_session_command "$init_sql" "$init_output" || return 1
  control_database="$(sed -n 's/^__DATABASE__//p' "$init_output")"
  control_backend_pid="$(sed -n 's/^__BACKEND_PID__//p' "$init_output")"
  [[ "$control_database" == postgres && "$control_backend_pid" =~ ^[0-9]+$ ]] \
    || { echo "restore control backend is not safely connected to the maintenance database" >&2; return 1; }

  # Database-local advisory locks cannot be owned by the maintenance-database
  # controller. A dedicated target coordinator serializes backup/restore and
  # later waits on each target-local replacement transaction without receiving
  # replacement SQL itself. The primary owns a session-level policy lock until
  # the hard connection fence is active; each replacement then owns its
  # transaction-level policy lock. Giving either lock to the coordinator would
  # self-deadlock the executor that must acquire it.
  start_psql_session coordinator target_coordinator_pid target_coordinator_in \
    target_coordinator_out target
  discover_target_coordinator_identity || return 1
  acquire_target_coordination_locks || return 1
  verify_restore_transaction_status_capability || return 1

  # Policy application and dump replacement deliberately run on disposable
  # workers. The maintenance controller remains outside the target and owns
  # only the connection fence; the target coordinator owns transaction-status
  # arbitration after each database-local replacement barrier.
  start_psql_session primary primary_worker_pid primary_worker_in primary_worker_out target
  verify_primary_target_identity || return 1
  acquire_primary_policy_lock || return 1

  [[ "$control_backend_pid" != "$target_coordinator_backend_pid" \
     && "$control_backend_pid" != "$primary_backend_pid" \
     && "$target_coordinator_backend_pid" != "$primary_backend_pid" ]] \
    || { echo "restore database sessions do not have distinct backend identities" >&2; return 1; }

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
  start_psql_session compensation compensation_worker_pid \
    compensation_worker_in compensation_worker_out target
  verify_compensation_target_identity || return 1
  [[ "$control_backend_pid" != "$compensation_backend_pid" \
     && "$target_coordinator_backend_pid" != "$compensation_backend_pid" \
     && "$primary_backend_pid" != "$compensation_backend_pid" ]] \
    || { echo "restore database sessions do not have distinct backend identities" >&2; return 1; }
}

set_target_database_connections() {
  local enabled="$1"
  local sql_file="$work_dir/database-connections-$enabled.sql"
  local output_file="$work_dir/database-connections-$enabled.out"
  local expected catalog_value catalog_count
  [[ "$enabled" == true || "$enabled" == false ]] || return 2
  if [[ "$enabled" == true ]]; then
    expected=t
  else
    expected=f
  fi
  {
    printf '\\set target_db %s\n' "$target_database"
    printf '%s\n' 'SET synchronous_commit TO on;'
    printf "SELECT format('ALTER DATABASE %%I WITH ALLOW_CONNECTIONS %s', :'target_db') \\\\gexec\n" \
      "$enabled"
    printf "%s\n" \
      "SELECT '__NORTHSTAR_ALLOW_CONNECTIONS__' || datallowconn::text FROM pg_catalog.pg_database WHERE datname = :'target_db';"
  } >"$sql_file"
  control_session_command "$sql_file" "$output_file" || return 1
  catalog_value="$(sed -n 's/^__NORTHSTAR_ALLOW_CONNECTIONS__//p' "$output_file")"
  catalog_count="$(awk 'index($0, "__NORTHSTAR_ALLOW_CONNECTIONS__") == 1 { count += 1 } END { print count + 0 }' "$output_file")"
  if [[ "$catalog_count" != 1 || "$catalog_value" != "$expected" ]]; then
    echo "database connection fence did not converge to ALLOW_CONNECTIONS=$enabled" >&2
    return 1
  fi
}

activate_target_database_fence() {
  local sql_file="$work_dir/database-fence.sql" session_counts remaining_sessions allowed_sessions
  fence_attempted=true
  if ! set_target_database_connections false; then
    fence_attempted=false
    return 1
  fi
  journal_append state ConnectionsDenied
  cat >"$sql_file" <<SQL
\set target_db $target_database
\set coordinator_pid $target_coordinator_backend_pid
\set primary_pid $primary_backend_pid
\set compensation_pid $compensation_backend_pid
SELECT COUNT(*) FILTER (
         WHERE pid NOT IN (:coordinator_pid, :primary_pid, :compensation_pid)
       )::text || ':' ||
       COUNT(*) FILTER (
         WHERE pid IN (:coordinator_pid, :primary_pid, :compensation_pid)
       )::text
FROM pg_stat_activity
WHERE datname = :'target_db';
SQL
  if ! control_session_command "$sql_file" "$work_dir/database-fence.out"; then
    set_target_database_connections true || true
    fence_attempted=false
    return 1
  fi
  session_counts="$(sed -n '/^[0-9][0-9]*:[0-9][0-9]*$/p' "$work_dir/database-fence.out")"
  if [[ ! "$session_counts" =~ ^[0-9]+:[0-9]+$ ]]; then
    echo "failed to identify the exact restore database sessions" >&2
    set_target_database_connections true || true
    fence_attempted=false
    return 1
  fi
  IFS=: read -r remaining_sessions allowed_sessions <<<"$session_counts"
  if (( remaining_sessions != 0 || allowed_sessions != 3 )); then
    echo "restore refused: $remaining_sessions other target database session(s) remain after the connection fence; stop Northstar and all database clients, then retry" >&2
    set_target_database_connections true || true
    fence_attempted=false
    return 1
  fi
  journal_append state OldWorkloadsDrained
  database_fence_active=true
  journal_append fence-active \
    "target-database=$target_database" \
    "maintenance-control-pid=$control_backend_pid" \
    "target-coordinator-pid=$target_coordinator_backend_pid" \
    "primary-executor-pid=$primary_backend_pid" \
    "compensation-executor-pid=$compensation_backend_pid"
}

release_target_database_fence() {
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
  if [[ "$restore_committed" == true ]]; then
    if [[ -z "$incoming_restore_xid" \
       || "$incoming_restore_status" != committed \
       || "$database_generation_state" != replacement ]]; then
      database_outcome_unknown=true
      echo "refusing to release the database fence without a committed replacement generation" >&2
      return 1
    fi
  elif [[ "$database_generation_state" != original ]]; then
    database_outcome_unknown=true
    echo "refusing to release the database fence before the original generation is restored" >&2
    return 1
  elif [[ "$incoming_restore_status" != not-started \
       && "$incoming_restore_status" != aborted \
       && ( "$rollback_restore_status" != committed || -z "$rollback_restore_xid" ) ]]; then
    database_outcome_unknown=true
    echo "refusing to release the database fence without a final replacement or compensation status" >&2
    return 1
  fi
  if ! set_target_database_connections true; then
    database_outcome_unknown=true
    echo "database replacement is final, but the connection fence could not be released" >&2
    return 1
  fi
  journal_append state ConnectionsEnabled
  database_fence_active=false
  fence_attempted=false
}

replace_database_from_dump() {
  local replacement_dump="$1" label="$2" grant_phase="$3"
  local worker_in="$4" worker_out="$5" transaction_kind="$6"
  local output_file="$work_dir/replace-$label.out"
  local grant_variables="$work_dir/replace-$label-grant-variables.sql"
  local nonce ready_token token xid_prefix xid_line xid_count barrier_key worker_kind worker_backend_pid
  local header_ok=true ready_ok=false stream_ok=true token_ok=false
  nonce="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
  ready_token="__NORTHSTAR_RESTORE_READY_${label}_${restore_id}_${nonce}__"
  token="__NORTHSTAR_RESTORE_DONE_${label}_${restore_id}_${nonce}__"
  xid_prefix="__NORTHSTAR_RESTORE_XID_${transaction_kind}_${restore_id}_${nonce}__"
  replacement_committed=false
  [[ -e "/proc/$$/fd/$worker_in" && -e "/proc/$$/fd/$worker_out" ]] || return 1
  case "$transaction_kind" in
    incoming)
      barrier_key="northstar-restore-$restore_id-incoming"
      worker_kind=primary
      worker_backend_pid="$primary_backend_pid"
      [[ "$label" == restored \
         && "$worker_in" == "$primary_worker_in" \
         && "$worker_out" == "$primary_worker_out" \
         && "$incoming_restore_status" == not-started \
         && "$rollback_restore_status" == not-started \
         && "$database_generation_state" == original ]] \
        || return 2
      ;;
    rollback)
      barrier_key="northstar-restore-$restore_id-rollback"
      worker_kind=compensation
      worker_backend_pid="$compensation_backend_pid"
      [[ "$label" == rollback \
         && "$worker_in" == "$compensation_worker_in" \
         && "$worker_out" == "$compensation_worker_out" \
         && "$incoming_restore_status" == committed \
         && "$rollback_restore_status" == not-started \
         && "$database_generation_state" == replacement ]] || return 2
      ;;
    *) return 2 ;;
  esac
  write_grant_policy_variables "$grant_variables" "$grant_phase" || return 1
  printf '\\set restore_barrier_key %s\n' "$barrier_key" >>"$grant_variables"
  : >"$output_file"

  if [[ "$restore_transaction_active" == true ]]; then
    database_outcome_unknown=true
    echo "refusing to overlap database replacement transactions" >&2
    return 2
  fi
  restore_transaction_active=true
  active_restore_kind="$transaction_kind"
  active_restore_barrier_key="$barrier_key"
  active_restore_barrier_label="$label"
  active_restore_worker="$worker_kind"
  active_restore_xid=""
  active_restore_destructive_sent=false
  if [[ "$transaction_kind" == incoming ]]; then
    incoming_restore_status=active
  else
    rollback_restore_status=active
  fi

  # Phase one establishes a transaction boundary before any destructive SQL is
  # sent. READY proves that the worker owns the unique transaction-level lock
  # and has published its top-level xid8. The parent must durably journal that
  # XID before it sends even the first destructive byte.
  {
    cat "$grant_variables" &&
    printf '%s\n' 'BEGIN;' &&
    printf "%s\n" \
      "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(:'restore_barrier_key', 0));" &&
    printf "SELECT '%s' || pg_catalog.pg_current_xact_id()::text;\n" "$xid_prefix" &&
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
    if [[ "$last_restore_transaction_kind" == "$transaction_kind" \
       && "$last_restore_transaction_status" == aborted ]]; then
      echo "$label database replacement failed before its destructive phase" >&2
      return 1
    fi
    database_outcome_unknown=true
    echo "$label database replacement failed READY with an unknown outcome" >&2
    return 2
  fi

  xid_line="$(sed -n "s/^${xid_prefix}//p" "$output_file")"
  xid_count="$(awk -v prefix="$xid_prefix" \
    'index($0, prefix) == 1 { count += 1 } END { print count + 0 }' "$output_file")"
  if [[ "$xid_count" != 1 || ! "$xid_line" =~ ^[1-9][0-9]{0,19}$ ]]; then
    {
      printf '%s\n' 'ROLLBACK;'
      printf '\\echo %s\n' "$token"
    } >&"$worker_in" 2>/dev/null || true
    psql_session_wait_token "$worker_out" "$token" "$output_file" 2>/dev/null || true
    settle_active_restore_transaction || return 2
    echo "$label database replacement published an invalid transaction ID" >&2
    return 1
  fi
  active_restore_xid="$xid_line"
  if ! journal_append database-transaction-intent "$transaction_kind" "$label" \
      "$active_restore_xid" "$barrier_key" \
      "target-database=$target_database" "worker-backend-pid=$worker_backend_pid"; then
    {
      printf '%s\n' 'ROLLBACK;'
      printf '\\echo %s\n' "$token"
    } >&"$worker_in" 2>/dev/null || true
    psql_session_wait_token "$worker_out" "$token" "$output_file" 2>/dev/null || true
    settle_active_restore_transaction || return 2
    echo "could not durably publish the $label replacement transaction ID" >&2
    return 1
  fi

  # Phase two is unreachable until the XID intent above has been fsynced. The
  # advisory transaction lock stays held through schema replacement, ACL
  # convergence and COMMIT.
  active_restore_destructive_sent=true
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
    && ! run_pg_client_without_parent_fds pg_restore "$replacement_dump" \
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
  # COMMIT input. The target coordinator first acquires the worker's transaction
  # lock and then reads pg_xact_status(xid8) in the same transaction.
  settle_active_restore_transaction || return 2
  if [[ "$last_restore_transaction_kind" != "$transaction_kind" \
     || "$last_restore_transaction_label" != "$label" \
     || "$last_restore_transaction_xid" != "$xid_line" ]]; then
    database_outcome_unknown=true
    echo "$label database replacement settled with a mismatched transaction identity" >&2
    return 2
  fi
  if [[ "$last_restore_transaction_status" == committed ]]; then
    [[ "$token_ok" == true ]] || {
      echo "$label database replacement committed, but its worker terminated before acknowledgement" >&2
      return 1
    }
    return 0
  fi
  if [[ "$last_restore_transaction_status" == aborted ]]; then
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
  if [[ "$database_generation_state" == replacement ]]; then
    if [[ "$incoming_restore_status" != committed ]]; then
      database_outcome_unknown=true
      echo "cannot compensate a replacement generation without its committed incoming XID" >&2
      return 1
    fi
    replacement_committed=false
    if ! replace_database_from_dump "$rollback_dump" rollback auto \
      "$compensation_worker_in" "$compensation_worker_out" rollback; then
      replacement_ok=false
    fi
    if [[ "$replacement_committed" != true \
       || "$rollback_restore_status" != committed \
       || "$database_generation_state" != original ]]; then
      database_ok=false
    fi
    [[ "$replacement_ok" == true || "$replacement_committed" == true ]] || database_ok=false
  elif [[ "$database_generation_state" != original ]]; then
    database_outcome_unknown=true
    echo "cannot compensate an unknown database generation" >&2
    return 1
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
  # This must be the first cleanup side effect. A second INT/TERM between the
  # re-entry guard and clearing EXIT would otherwise recursively exit from the
  # guard, while a signal after clearing EXIT could bypass cleanup entirely.
  trap '' INT TERM
  local status="$1" compensation_ok=true fence_ok=true cleanup_ok=true
  if [[ "$cleanup_running" == true ]]; then
    trap - ERR EXIT
    exit "$status"
  fi
  cleanup_running=true
  trap - ERR EXIT
  set +e

  if [[ "$restore_committed" == true ]]; then
    # The replay floor has made the new data plane authoritative, so cleanup
    # must never compensate it. It must still prove that no worker transaction
    # is active and that the incoming XID committed before reopening the
    # database.
    if ! settle_active_restore_transaction; then
      database_outcome_unknown=true
    elif [[ "$incoming_restore_status" != committed \
         || "$database_generation_state" != replacement ]]; then
      database_outcome_unknown=true
    fi
  elif [[ "$compensation_required" == true ]]; then
    if ! settle_active_restore_transaction; then
      database_outcome_unknown=true
    fi
    compensate_restore || compensation_ok=false
  fi

  if [[ "$fence_attempted" == true ]]; then
    if [[ "$database_outcome_unknown" == true ]]; then
      fence_ok=false
      echo "PostgreSQL remains fail-closed because the restore outcome is unknown." >&2
    elif [[ "$compensation_ok" == true || "$restore_committed" == true ]]; then
      release_target_database_fence || fence_ok=false
    else
      fence_ok=false
      echo "PostgreSQL remains fail-closed because compensation was incomplete." >&2
    fi
  fi
  close_db_sessions || cleanup_ok=false

  if [[ "$compensation_ok" == true && "$fence_ok" == true \
     && "$cleanup_ok" == true ]]; then
    if [[ "$restore_committed" != true ]]; then
      remove_cutover_dir || cleanup_ok=false
    fi
    if [[ "$cleanup_ok" == true ]]; then
      remove_work_dir || cleanup_ok=false
    fi
  fi
  if [[ "$compensation_ok" != true || "$fence_ok" != true \
     || "$cleanup_ok" != true ]]; then
    journal_append state RecoveryRequired || true
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

# The target coordinator owns the database-local advisory maintenance fence
# shared with backup. The controller is deliberately connected elsewhere and
# owns only the hard connection fence. The coordinator also arbitrates each
# replacement XID after its transaction-local barrier; neither fence is
# represented as an application-writer lock.
establish_restore_database_authorities
run_pg_client_without_parent_fds pg_dump --format=custom --compress=9 --no-owner --no-acl \
  --file="$rollback_dump"
chmod 0600 "$rollback_dump"
run_pg_client_without_parent_fds pg_restore --list "$rollback_dump" >/dev/null
fsync_path "$rollback_dump"
fsync_path "$rollback_set"
journal_append rollback-ready "$rollback_set"
journal_append state Prepared

# ALLOW_CONNECTIONS=false is the fail-closed boundary. The restore does not
# terminate sessions: operators must stop the application and all clients first.
# The independent compensation worker is opened before the fence, so it remains
# available even if the primary replacement worker terminates on a SQL error. A
# crash leaves the target unavailable rather than exposing a half-switched data
# plane.
start_compensation_worker
activate_target_database_fence
release_primary_policy_lock_after_fence
verify_manifest_objects "$old_manifest" "$resolved_upload" "${cutover_dir##*/}" \
  || { echo "upload root changed while the database fence was being installed" >&2; exit 1; }
journal_append state BackupVerified
compensation_required=true
journal_append database-switch-intent
replacement_committed=false
if ! replace_database_from_dump "$payload_dir/database.dump" restored exact \
  "$primary_worker_in" "$primary_worker_out" incoming; then
  false
fi
journal_append database-switch-done
journal_append state RestoreApplied
journal_append state RolesReconciled

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
journal_append state PostRestoreVerified
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

# The replay floor and the already-journaled committed incoming XID now make the
# replacement generation authoritative. There is no database marker to retire;
# the terminal-state guard below is the only path that may reopen connections.
release_target_database_fence
close_db_sessions
if [[ "$preserve_work" != true ]]; then
  remove_cutover_dir
  remove_work_dir
else
  echo "restore committed, but journal cleanup was retained for operator inspection: $cutover_dir" >&2
fi
compensation_required=false
journal_append state Completed
trap - ERR EXIT INT TERM

echo "restore complete: database and $resolved_upload"
echo "previous upload files retained at: $previous_uploads"
echo "pre-restore database retained at: $rollback_dump"
