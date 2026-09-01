#!/usr/bin/env bash
set -euo pipefail

umask 077
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
for command in python3 openssl sha256sum tar; do
  command -v "$command" >/dev/null || { echo "required command is unavailable: $command" >&2; exit 1; }
done

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/northstar-backup-security.XXXXXX")"
cleanup() {
  case "$fixture_root" in
    "${TMPDIR:-/tmp}"/northstar-backup-security.*) rm -rf --one-file-system -- "$fixture_root" ;;
    *) echo "refusing to clean unexpected fixture path" >&2 ;;
  esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 "$fixture_root/bin" "$fixture_root/source"
cat > "$fixture_root/bin/pg_restore" <<'EOF'
#!/bin/sh
if test "$1" = "--list"; then
  grep -q '^NORTHSTAR_OFFLINE_DATABASE_FIXTURE$' "$2"
else
  exit 0
fi
EOF
cat > "$fixture_root/bin/pg_dump" <<'EOF'
#!/bin/sh
destination=
for argument in "$@"; do
  case "$argument" in
    --file=*) destination=${argument#--file=} ;;
  esac
done
test -n "$destination" || exit 1
printf '%s\n' NORTHSTAR_OFFLINE_DATABASE_FIXTURE > "$destination"
EOF
cat > "$fixture_root/bin/psql" <<'EOF'
#!/bin/sh
case "$*" in
  *'SHOW server_version'*) printf '%s\n' fixture ;;
  *'COUNT(*) FROM _sqlx_migrations'*) printf '%s\n' 0 ;;
  *'FROM public.upload_slots'*) exit 0 ;;
  *)
    while IFS= read -r line; do
      case "$line" in
        *pg_try_advisory_lock*) printf '%s\n' __LOCK_OK__ ;;
        *"SELECT '__FENCE_ALIVE__'"*) printf '%s\n' __FENCE_ALIVE__ ;;
        '\echo '*) printf '%s\n' "${line#\\echo }" ;;
        '\q') exit 0 ;;
      esac
    done
    ;;
esac
EOF
cat > "$fixture_root/bin/createdb" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fixture_root/bin/dropdb" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$fixture_root/bin/initdb" <<'EOF'
#!/bin/sh
while test "$#" -gt 0; do
  if test "$1" = -D; then
    mkdir -p "$2"
    : > "$2/postgresql.conf"
    exit 0
  fi
  shift
done
exit 1
EOF
cat > "$fixture_root/bin/pg_ctl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0500 "$fixture_root/bin/pg_restore" "$fixture_root/bin/pg_dump" \
  "$fixture_root/bin/psql" "$fixture_root/bin/createdb" "$fixture_root/bin/dropdb" \
  "$fixture_root/bin/initdb" "$fixture_root/bin/pg_ctl"
export PATH="$fixture_root/bin:$PATH"
# This fixture deliberately exercises the compatibility policy. Production is
# the script default and is covered by fail-closed configuration assertions.
export BACKUP_SECURITY_POLICY=development-legacy

printf '%s\n' NORTHSTAR_OFFLINE_DATABASE_FIXTURE > "$fixture_root/source/database.dump"
printf '%s\n' NORTHSTAR_OFFLINE_CONTENTS_FIXTURE > "$fixture_root/source/database.contents"
mkdir -m 0700 "$fixture_root/source/uploads"
printf '%s\n' immutable-upload > \
  "$fixture_root/source/uploads/00000000-0000-4000-8000-000000000001"
tar --create --gzip --file="$fixture_root/source/uploads.tar.gz" \
  --directory="$fixture_root/source/uploads" .
python3 "$script_dir/verify-upload-archive.py" "$fixture_root/source/uploads.tar.gz"

openssl genpkey -algorithm ED25519 -out "$fixture_root/signing.key" 2>/dev/null
openssl pkey -in "$fixture_root/signing.key" -pubout \
  -out "$fixture_root/signing.pub" 2>/dev/null
openssl genpkey -algorithm ED25519 -out "$fixture_root/wrong.key" 2>/dev/null
openssl pkey -in "$fixture_root/wrong.key" -pubout \
  -out "$fixture_root/wrong.pub" 2>/dev/null
chmod 0600 "$fixture_root/signing.key" "$fixture_root/wrong.key"

mkdir -m 0700 "$fixture_root/sequence-state"
for index in 1 2 3 4 5 6 7 8; do
  python3 "$script_dir/backup-security.py" reserve-sequence \
    "$fixture_root/sequence-state/current" > "$fixture_root/sequence-state/result-$index" &
done
wait
test "$(awk '{print $1}' "$fixture_root"/sequence-state/result-* | sort -u | wc -l)" -eq 1
test "$(awk '{print $2}' "$fixture_root"/sequence-state/result-* | sort -n | tr '\n' ' ')" \
  = "1 2 3 4 5 6 7 8 "
test "$(stat -c '%a' "$fixture_root/sequence-state/current")" = 600

public_key_id() {
  local key="$1" der="$fixture_root/public.der"
  openssl pkey -pubin -in "$key" -outform DER -out "$der" 2>/dev/null
  printf 'sha256:%s' "$(sha256sum "$der" | awk '{print $1}')"
  rm -- "$der"
}

make_signed_fixture() {
  local destination="$1" generation="$2" sequence="$3"
  mkdir -m 0700 "$destination"
  cp -- "$fixture_root/source/database.dump" "$destination/database.dump"
  cp -- "$fixture_root/source/database.contents" "$destination/database.contents"
  cp -- "$fixture_root/source/uploads.tar.gz" "$destination/uploads.tar.gz"
  local database_digest contents_digest upload_digest key_id
  database_digest="$(sha256sum "$destination/database.dump" | awk '{print $1}')"
  contents_digest="$(sha256sum "$destination/database.contents" | awk '{print $1}')"
  upload_digest="$(sha256sum "$destination/uploads.tar.gz" | awk '{print $1}')"
  key_id="$(public_key_id "$fixture_root/signing.pub")"
  cat > "$destination/manifest.txt" <<EOF
format=northstar-backup-v2
manifest_version=2
backup_generation=$generation
backup_sequence=$sequence
created_at=2026-08-29T00:00:00Z
northstar_version=fixture-1
postgresql_version=fixture
successful_migrations=0
encryption=none
signature=openssl-ed25519
signing_key_id=$key_id
database_archive=database.dump
database_archive_sha256=$database_digest
database_plain_sha256=$database_digest
database_contents=database.contents
database_contents_archive_sha256=$contents_digest
database_contents_plain_sha256=$contents_digest
upload_archive=uploads.tar.gz
upload_archive_sha256=$upload_digest
upload_plain_sha256=$upload_digest
upload_consistency=immutable-final-files
EOF
  python3 "$script_dir/backup-security.py" validate-manifest "$destination/manifest.txt"
  openssl pkeyutl -sign -rawin -inkey "$fixture_root/signing.key" \
    -in "$destination/manifest.txt" -out "$destination/manifest.sig" 2>/dev/null
  (cd "$destination" && sha256sum \
    database.dump database.contents uploads.tar.gz manifest.txt manifest.sig > SHA256SUMS)
  touch "$destination/READY"
}

expect_failure() {
  local label="$1"
  shift
  if "$@" >"$fixture_root/expected-failure.log" 2>&1; then
    echo "expected failure was accepted: $label" >&2
    exit 1
  fi
}

expect_failure production-verify-missing-trust \
  env BACKUP_SECURITY_POLICY=production \
  bash "$script_dir/verify-backup.sh" "$fixture_root/source"
expect_failure production-backup-missing-capabilities \
  env BACKUP_SECURITY_POLICY=production \
  bash "$script_dir/backup.sh" --output "$fixture_root/production-must-not-exist"
test ! -e "$fixture_root/production-must-not-exist"

generation_one=11111111-1111-4111-8111-111111111111
generation_two=22222222-2222-4222-8222-222222222222
make_signed_fixture "$fixture_root/sequence-1" "$generation_one" 1
make_signed_fixture "$fixture_root/sequence-2" "$generation_one" 2
make_signed_fixture "$fixture_root/new-generation" "$generation_two" 1

bash "$script_dir/verify-backup.sh" "$fixture_root/sequence-1" \
  --require-signature --public-key-file "$fixture_root/signing.pub" >/dev/null
expect_failure wrong-public-key bash "$script_dir/verify-backup.sh" "$fixture_root/sequence-1" \
  --require-signature --public-key-file "$fixture_root/wrong.pub"

cp -a -- "$fixture_root/sequence-1" "$fixture_root/tampered-payload"
printf '%s\n' attacker >> "$fixture_root/tampered-payload/database.dump"
expect_failure tampered-payload bash "$script_dir/verify-backup.sh" \
  "$fixture_root/tampered-payload" --require-signature \
  --public-key-file "$fixture_root/signing.pub"

cp -a -- "$fixture_root/sequence-1" "$fixture_root/tampered-manifest"
sed -i 's/backup_sequence=1/backup_sequence=9/' "$fixture_root/tampered-manifest/manifest.txt"
expect_failure tampered-manifest bash "$script_dir/verify-backup.sh" \
  "$fixture_root/tampered-manifest" --require-signature \
  --public-key-file "$fixture_root/signing.pub"

restore_state="$fixture_root/restore-state"
python3 "$script_dir/backup-security.py" commit-restore-state \
  "$fixture_root/sequence-1/manifest.txt" "$restore_state"
expect_failure replayed-sequence bash "$script_dir/verify-backup.sh" \
  "$fixture_root/sequence-1" --require-signature \
  --public-key-file "$fixture_root/signing.pub" --rollback-state-file "$restore_state"
bash "$script_dir/verify-backup.sh" "$fixture_root/sequence-2" --require-signature \
  --public-key-file "$fixture_root/signing.pub" --rollback-state-file "$restore_state" >/dev/null
python3 "$script_dir/backup-security.py" commit-restore-state \
  "$fixture_root/sequence-2/manifest.txt" "$restore_state"
highest_manifest_digest="$(sed -n 's/^manifest_sha256=//p' "$restore_state")"
bash "$script_dir/verify-backup.sh" "$fixture_root/sequence-1" --require-signature \
  --public-key-file "$fixture_root/signing.pub" --rollback-state-file "$restore_state" \
  --allow-rollback >/dev/null
python3 "$script_dir/backup-security.py" commit-restore-state \
  "$fixture_root/sequence-1/manifest.txt" "$restore_state"
grep -qx 'sequence=2' "$restore_state"
grep -qx "manifest_sha256=$highest_manifest_digest" "$restore_state"

expect_failure unapproved-generation bash "$script_dir/verify-backup.sh" \
  "$fixture_root/new-generation" --require-signature \
  --public-key-file "$fixture_root/signing.pub" --rollback-state-file "$restore_state"
bash "$script_dir/verify-backup.sh" "$fixture_root/new-generation" --require-signature \
  --public-key-file "$fixture_root/signing.pub" --rollback-state-file "$restore_state" \
  --allow-generation-change >/dev/null

mkdir -m 0700 "$fixture_root/legacy"
cp -- "$fixture_root/source/database.dump" "$fixture_root/legacy/database.dump"
cp -- "$fixture_root/source/database.contents" "$fixture_root/legacy/database.contents"
cp -- "$fixture_root/source/uploads.tar.gz" "$fixture_root/legacy/uploads.tar.gz"
cat > "$fixture_root/legacy/manifest.txt" <<'EOF'
format=northstar-backup-v1
created_at=20260829T000000Z
postgresql_version=fixture
successful_migrations=0
database_archive=database.dump
upload_archive=uploads.tar.gz
upload_consistency=immutable-final-files
EOF
(cd "$fixture_root/legacy" && sha256sum \
  database.dump database.contents uploads.tar.gz manifest.txt > SHA256SUMS)
touch "$fixture_root/legacy/READY"
bash "$script_dir/verify-backup.sh" "$fixture_root/legacy" >/dev/null
expect_failure required-signature-rejects-legacy bash "$script_dir/verify-backup.sh" \
  "$fixture_root/legacy" --require-signature --public-key-file "$fixture_root/signing.pub"

# Exercise the producer itself with fake PostgreSQL clients. The URL has no
# password and is never printed; run-postgres.py still exercises its file-safe
# process environment path.
mkdir -m 0700 "$fixture_root/producer-output" "$fixture_root/producer-uploads"
cp -- "$fixture_root/source/uploads/00000000-0000-4000-8000-000000000001" \
  "$fixture_root/producer-uploads/00000000-0000-4000-8000-000000000001"
DATABASE_URL=postgresql://fixture@127.0.0.1/fixture \
  bash "$script_dir/backup.sh" --output "$fixture_root/producer-output" \
  --upload-dir "$fixture_root/producer-uploads" \
  --signing-key-file "$fixture_root/signing.key" --require-signature \
  --northstar-version fixture-1 >/dev/null
producer_backup="$(find "$fixture_root/producer-output" -mindepth 1 -maxdepth 1 \
  -type d -name 'northstar-*' -print -quit)"
test -n "$producer_backup"
bash "$script_dir/verify-backup.sh" "$producer_backup" --require-signature \
  --public-key-file "$fixture_root/signing.pub" >/dev/null
grep -qx 'format=northstar-backup-v2' "$producer_backup/manifest.txt"

if command -v age >/dev/null && command -v age-keygen >/dev/null; then
  age-keygen -o "$fixture_root/age.key" >"$fixture_root/age-keygen.log" 2>&1
  age-keygen -o "$fixture_root/wrong-age.key" >"$fixture_root/wrong-age-keygen.log" 2>&1
  chmod 0600 "$fixture_root/age.key" "$fixture_root/wrong-age.key"
  age_recipient="$(sed -n 's/^# public key: //p' "$fixture_root/age.key")"
  printf '%s\n' "$age_recipient" > "$fixture_root/age.recipients"

  encrypted="$fixture_root/encrypted"
  mkdir -m 0700 "$encrypted"
  age --encrypt --recipients-file "$fixture_root/age.recipients" \
    --output "$encrypted/database.dump.age" "$fixture_root/source/database.dump"
  age --encrypt --recipients-file "$fixture_root/age.recipients" \
    --output "$encrypted/database.contents.age" "$fixture_root/source/database.contents"
  age --encrypt --recipients-file "$fixture_root/age.recipients" \
    --output "$encrypted/uploads.tar.gz.age" "$fixture_root/source/uploads.tar.gz"
  database_stored="$(sha256sum "$encrypted/database.dump.age" | awk '{print $1}')"
  contents_stored="$(sha256sum "$encrypted/database.contents.age" | awk '{print $1}')"
  uploads_stored="$(sha256sum "$encrypted/uploads.tar.gz.age" | awk '{print $1}')"
  database_plain="$(sha256sum "$fixture_root/source/database.dump" | awk '{print $1}')"
  contents_plain="$(sha256sum "$fixture_root/source/database.contents" | awk '{print $1}')"
  uploads_plain="$(sha256sum "$fixture_root/source/uploads.tar.gz" | awk '{print $1}')"
  key_id="$(public_key_id "$fixture_root/signing.pub")"
  cat > "$encrypted/manifest.txt" <<EOF
format=northstar-backup-v2
manifest_version=2
backup_generation=$generation_one
backup_sequence=3
created_at=2026-08-29T00:00:00Z
northstar_version=fixture-1
postgresql_version=fixture
successful_migrations=0
encryption=age
signature=openssl-ed25519
signing_key_id=$key_id
database_archive=database.dump.age
database_archive_sha256=$database_stored
database_plain_sha256=$database_plain
database_contents=database.contents.age
database_contents_archive_sha256=$contents_stored
database_contents_plain_sha256=$contents_plain
upload_archive=uploads.tar.gz.age
upload_archive_sha256=$uploads_stored
upload_plain_sha256=$uploads_plain
upload_consistency=immutable-final-files
EOF
  openssl pkeyutl -sign -rawin -inkey "$fixture_root/signing.key" \
    -in "$encrypted/manifest.txt" -out "$encrypted/manifest.sig" 2>/dev/null
  (cd "$encrypted" && sha256sum database.dump.age database.contents.age \
    uploads.tar.gz.age manifest.txt manifest.sig > SHA256SUMS)
  touch "$encrypted/READY"

  bash "$script_dir/verify-backup.sh" "$encrypted" --require-signature \
    --public-key-file "$fixture_root/signing.pub" \
    --age-identity-file "$fixture_root/age.key" >/dev/null
  bash "$script_dir/verify-backup.sh" "$encrypted" --require-signature \
    --public-key-file "$fixture_root/signing.pub" --metadata-only >/dev/null
  expect_failure wrong-age-identity bash "$script_dir/verify-backup.sh" "$encrypted" \
    --require-signature --public-key-file "$fixture_root/signing.pub" \
    --age-identity-file "$fixture_root/wrong-age.key"

  mkdir -m 0700 "$fixture_root/encrypted-output" "$fixture_root/encrypted-scratch"
  DATABASE_URL=postgresql://fixture@127.0.0.1/fixture \
    bash "$script_dir/backup.sh" --output "$fixture_root/encrypted-output" \
    --upload-dir "$fixture_root/producer-uploads" \
    --signing-key-file "$fixture_root/signing.key" --require-signature \
    --age-recipient-file "$fixture_root/age.recipients" \
    --plaintext-staging-dir "$fixture_root/encrypted-scratch" \
    --northstar-version fixture-1 >/dev/null
  encrypted_producer="$(find "$fixture_root/encrypted-output" -mindepth 1 -maxdepth 1 \
    -type d -name 'northstar-*' -print -quit)"
  test -n "$encrypted_producer"
  test -z "$(find "$fixture_root/encrypted-scratch" -mindepth 1 -print -quit)"
  test ! -e "$encrypted_producer/database.dump"
  test -f "$encrypted_producer/database.dump.age"
  bash "$script_dir/verify-backup.sh" "$encrypted_producer" --require-signature \
    --public-key-file "$fixture_root/signing.pub" \
    --age-identity-file "$fixture_root/age.key" >/dev/null
else
  echo "age is unavailable; encrypted fixture was skipped" >&2
fi

echo "backup security offline fixtures passed"
