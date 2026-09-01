#!/usr/bin/env bash
set -euo pipefail

umask 077
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
backup_dir=""
public_key_file="${BACKUP_VERIFY_KEY_FILE:-}"
require_signature="${BACKUP_REQUIRE_SIGNATURE:-false}"
age_identity_file="${BACKUP_AGE_IDENTITY_FILE:-}"
rollback_state_file="${BACKUP_ROLLBACK_STATE_FILE:-}"
allow_rollback="${BACKUP_ALLOW_ROLLBACK:-false}"
allow_generation_change="${BACKUP_ALLOW_GENERATION_CHANGE:-false}"
security_policy="${BACKUP_SECURITY_POLICY:-production}"
materialize_dir=""
metadata_only=false

usage() {
  cat >&2 <<EOF
usage: $0 BACKUP_DIRECTORY [OPTIONS]

Authenticate and verify a Northstar backup before any payload is consumed.

Options:
  --public-key-file FILE       Trusted OpenSSL Ed25519 public key
  --require-signature          Reject unsigned and legacy v1 backups
  --age-identity-file FILE     age private identity used after authentication
  --rollback-state-file FILE   Enforce generation/sequence replay protection
  --allow-rollback             Deliberately allow an equal/older sequence
  --allow-generation-change    Trust a new backup generation deliberately
  --materialize-dir DIR        Leave verified plaintext payloads in empty DIR
  --metadata-only              Verify signature/ciphertext without decrypting
  --development-insecure-legacy
                               Explicitly permit legacy/unsigned development backups
  -h, --help                   Show this help

Environment equivalents:
  BACKUP_VERIFY_KEY_FILE, BACKUP_REQUIRE_SIGNATURE,
  BACKUP_AGE_IDENTITY_FILE, BACKUP_ROLLBACK_STATE_FILE,
  BACKUP_ALLOW_ROLLBACK, BACKUP_ALLOW_GENERATION_CHANGE.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-key-file) public_key_file="${2:?missing public key file}"; shift 2 ;;
    --require-signature) require_signature=true; shift ;;
    --age-identity-file) age_identity_file="${2:?missing age identity file}"; shift 2 ;;
    --rollback-state-file) rollback_state_file="${2:?missing rollback state file}"; shift 2 ;;
    --allow-rollback) allow_rollback=true; shift ;;
    --allow-generation-change) allow_generation_change=true; shift ;;
    --materialize-dir) materialize_dir="${2:?missing materialization directory}"; shift 2 ;;
    --metadata-only) metadata_only=true; shift ;;
    --development-insecure-legacy) security_policy=development-legacy; shift ;;
    -h|--help) usage; exit 0 ;;
    --*) usage; exit 2 ;;
    *)
      [[ -z "$backup_dir" ]] || { usage; exit 2; }
      backup_dir="$1"
      shift
      ;;
  esac
done
[[ -n "$backup_dir" ]] || { usage; exit 2; }

case "$security_policy" in
  production)
    require_signature=true
    allow_legacy=false
    ;;
  development-legacy)
    allow_legacy=true
    printf '%s\n' \
      'WARNING: development-legacy verification policy accepts backups that are unsuitable for production.' >&2
    ;;
  *)
    echo "BACKUP_SECURITY_POLICY must be production or development-legacy" >&2
    exit 2
    ;;
esac

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

# Validate every production trust capability before copying, decrypting or
# materializing any backup payload.
if [[ "$security_policy" == production ]]; then
  command -v grep >/dev/null \
    || { echo "production verification requires grep" >&2; exit 1; }
  [[ -n "$public_key_file" ]] \
    || { echo "production verification requires an Ed25519 public key file" >&2; exit 2; }
  [[ -f "$public_key_file" && ! -L "$public_key_file" && -r "$public_key_file" ]] \
    || { echo "verification key must be a readable regular non-symlink file" >&2; exit 2; }
  command -v openssl >/dev/null \
    || { echo "production verification requires openssl" >&2; exit 1; }
  openssl pkey -pubin -in "$public_key_file" -text_pub -noout 2>/dev/null \
    | grep -q 'ED25519' \
    || { echo "verification key must be an OpenSSL Ed25519 public key" >&2; exit 2; }
  [[ -n "$rollback_state_file" ]] \
    || { echo "production verification requires a persistent rollback-state file" >&2; exit 2; }
  if [[ "$metadata_only" != true ]]; then
    [[ -n "$age_identity_file" ]] \
      || { echo "production verification requires an age identity file" >&2; exit 2; }
    [[ -f "$age_identity_file" && ! -L "$age_identity_file" && -r "$age_identity_file" ]] \
      || { echo "age identity must be a readable regular non-symlink file" >&2; exit 2; }
    grep -q '^AGE-SECRET-KEY-1' "$age_identity_file" \
      || { echo "production age identity file contains no native age identity" >&2; exit 2; }
  fi
fi

for command in python3 sha256sum stat cp; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done
[[ -d "$backup_dir" && ! -L "$backup_dir" ]] \
  || { echo "backup path must be a real directory" >&2; exit 2; }
backup_dir="$(cd "$backup_dir" && pwd -P)"
scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-backup-verify.XXXXXX")"
cleanup() {
  case "$scratch_dir" in
    "${TMPDIR:-/tmp}"/northstar-backup-verify.*) rm -rf --one-file-system -- "$scratch_dir" ;;
    *) echo "refusing to clean unexpected verification scratch path" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ -f "$backup_dir/manifest.txt" && ! -L "$backup_dir/manifest.txt" ]] \
  || { echo "backup manifest must be a regular non-symlink file" >&2; exit 1; }
trusted_manifest="$scratch_dir/manifest.txt"
cp -- "$backup_dir/manifest.txt" "$trusted_manifest"
chmod 0600 "$trusted_manifest"
python3 "$script_dir/backup-security.py" validate-manifest "$trusted_manifest"
format="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" format)"

signature=none
if [[ "$format" == northstar-backup-v1 ]]; then
  [[ "$allow_legacy" == true ]] \
    || { echo "legacy v1 backup is disabled by policy" >&2; exit 1; }
  [[ "$require_signature" == false ]] \
    || { echo "legacy v1 backup cannot satisfy required signature policy" >&2; exit 1; }
  [[ -z "$rollback_state_file" ]] \
    || { echo "legacy v1 backup cannot satisfy rollback protection" >&2; exit 1; }
else
  encryption="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" encryption)"
  if [[ "$security_policy" == production && "$encryption" != age ]]; then
    echo "production verification requires an age-encrypted backup" >&2
    exit 1
  fi
  signature="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" signature)"
  if [[ "$signature" == none ]]; then
    [[ "$require_signature" == false ]] \
      || { echo "backup signature is required by policy" >&2; exit 1; }
    [[ -z "$rollback_state_file" ]] \
      || { echo "rollback protection requires an authenticated manifest" >&2; exit 1; }
  else
    command -v openssl >/dev/null || { echo "required command is unavailable: openssl" >&2; exit 1; }
    [[ -n "$public_key_file" ]] \
      || { echo "signed backup requires a trusted public key file" >&2; exit 1; }
    [[ -f "$public_key_file" && ! -L "$public_key_file" && -r "$public_key_file" ]] \
      || { echo "verification key must be a readable regular non-symlink file" >&2; exit 2; }
    [[ -f "$backup_dir/manifest.sig" && ! -L "$backup_dir/manifest.sig" \
       && "$(stat -c '%s' "$backup_dir/manifest.sig")" == 64 ]] \
      || { echo "Ed25519 manifest signature must be a 64-byte regular file" >&2; exit 1; }
    trusted_signature="$scratch_dir/manifest.sig"
    cp -- "$backup_dir/manifest.sig" "$trusted_signature"
    chmod 0600 "$trusted_signature"
    [[ "$(stat -c '%s' "$trusted_signature")" == 64 ]] \
      || { echo "Ed25519 manifest signature changed while it was read" >&2; exit 1; }
    openssl pkey -pubin -in "$public_key_file" -text_pub -noout 2>/dev/null \
      | grep -q 'ED25519' \
      || { echo "verification key must use Ed25519" >&2; exit 1; }
    openssl pkey -pubin -in "$public_key_file" -outform DER \
      -out "$scratch_dir/public.der" 2>/dev/null
    actual_key_id="sha256:$(sha256sum "$scratch_dir/public.der" | awk '{print $1}')"
    expected_key_id="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" signing_key_id)"
    [[ "$actual_key_id" == "$expected_key_id" ]] \
      || { echo "verification key ID does not match the signed manifest" >&2; exit 1; }
    openssl pkeyutl -verify -pubin -inkey "$public_key_file" -rawin \
      -in "$trusted_manifest" -sigfile "$trusted_signature" \
      >/dev/null 2>&1 \
      || { echo "backup manifest signature verification failed" >&2; exit 1; }
  fi
fi

# The manifest is authenticated before these signed ciphertext digests are
# trusted. No decryption or PostgreSQL parsing has occurred at this point.
artifact_args=(--manifest "$trusted_manifest")
[[ "$signature" != none ]] && artifact_args+=(--signature "$trusted_signature")
python3 "$script_dir/backup-security.py" verify-artifacts "$backup_dir" "${artifact_args[@]}"

if [[ -n "$rollback_state_file" ]]; then
  rollback_args=()
  [[ "$allow_rollback" == true ]] && rollback_args+=(--allow-rollback)
  [[ "$allow_generation_change" == true ]] && rollback_args+=(--allow-generation-change)
  python3 "$script_dir/backup-security.py" check-rollback \
    "$trusted_manifest" "$rollback_state_file" "${rollback_args[@]}"
fi

if [[ "$metadata_only" == true ]]; then
  [[ -z "$materialize_dir" ]] \
    || { echo "--metadata-only and --materialize-dir cannot be combined" >&2; exit 2; }
  echo "backup metadata and stored payloads verified: $backup_dir"
  exit 0
fi

for command in pg_restore cp find; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done

materialize_is_temporary=false
if [[ -z "$materialize_dir" ]]; then
  materialize_dir="$scratch_dir/payload"
  mkdir -m 0700 "$materialize_dir"
  materialize_is_temporary=true
else
  [[ -d "$materialize_dir" && ! -L "$materialize_dir" ]] \
    || { echo "materialization target must be a pre-created real directory" >&2; exit 2; }
  [[ -z "$(find "$materialize_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] \
    || { echo "materialization target must be empty" >&2; exit 2; }
  materialize_dir="$(cd "$materialize_dir" && pwd -P)"
  case "$materialize_dir" in
    "$backup_dir"|"$backup_dir"/*) echo "materialization target must be outside the backup" >&2; exit 2 ;;
  esac
  chmod 0700 "$materialize_dir"
fi

if [[ "$format" == northstar-backup-v1 ]]; then
  cp -- "$backup_dir/database.dump" "$materialize_dir/database.dump"
  cp -- "$backup_dir/database.contents" "$materialize_dir/database.contents"
  cp -- "$backup_dir/uploads.tar.gz" "$materialize_dir/uploads.tar.gz"
else
  encryption="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" encryption)"
  database_archive="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" database_archive)"
  database_contents="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" database_contents)"
  upload_archive="$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" upload_archive)"
  if [[ "$encryption" == age ]]; then
    command -v age >/dev/null || { echo "required command is unavailable: age" >&2; exit 1; }
    [[ -n "$age_identity_file" ]] \
      || { echo "encrypted backup requires an age identity file" >&2; exit 1; }
    [[ -f "$age_identity_file" && ! -L "$age_identity_file" && -r "$age_identity_file" ]] \
      || { echo "age identity must be a readable regular non-symlink file" >&2; exit 2; }
    identity_mode="$(stat -c '%a' "$age_identity_file")"
    (( (8#$identity_mode & 077) == 0 )) || [[ "$age_identity_file" == /run/secrets/* ]] \
      || { echo "age identity must not be accessible to group or other users" >&2; exit 2; }
    age --decrypt --identity "$age_identity_file" \
      --output "$materialize_dir/database.dump" "$backup_dir/$database_archive"
    age --decrypt --identity "$age_identity_file" \
      --output "$materialize_dir/database.contents" "$backup_dir/$database_contents"
    age --decrypt --identity "$age_identity_file" \
      --output "$materialize_dir/uploads.tar.gz" "$backup_dir/$upload_archive"
  else
    cp -- "$backup_dir/$database_archive" "$materialize_dir/database.dump"
    cp -- "$backup_dir/$database_contents" "$materialize_dir/database.contents"
    cp -- "$backup_dir/$upload_archive" "$materialize_dir/uploads.tar.gz"
  fi
  [[ "$(sha256sum "$materialize_dir/database.dump" | awk '{print $1}')" \
      == "$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" database_plain_sha256)" ]] \
    || { echo "plaintext database digest verification failed" >&2; exit 1; }
  [[ "$(sha256sum "$materialize_dir/database.contents" | awk '{print $1}')" \
      == "$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" database_contents_plain_sha256)" ]] \
    || { echo "plaintext database contents digest verification failed" >&2; exit 1; }
  [[ "$(sha256sum "$materialize_dir/uploads.tar.gz" | awk '{print $1}')" \
      == "$(python3 "$script_dir/backup-security.py" field "$trusted_manifest" upload_plain_sha256)" ]] \
    || { echo "plaintext upload digest verification failed" >&2; exit 1; }
fi
chmod 0600 "$materialize_dir/database.dump" "$materialize_dir/database.contents" "$materialize_dir/uploads.tar.gz"
pg_restore --list "$materialize_dir/database.dump" >/dev/null
python3 "$script_dir/verify-upload-archive.py" "$materialize_dir/uploads.tar.gz"
cp -- "$trusted_manifest" "$materialize_dir/manifest.txt"
[[ "$signature" == none ]] || cp -- "$trusted_signature" "$materialize_dir/manifest.sig"
chmod 0600 "$materialize_dir/manifest.txt"
[[ "$signature" == none ]] || chmod 0600 "$materialize_dir/manifest.sig"

if [[ "$materialize_is_temporary" == true ]]; then
  echo "backup verified: $backup_dir"
else
  echo "backup verified and materialized: $backup_dir"
fi
