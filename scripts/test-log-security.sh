#!/bin/sh
set -eu
set +x

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

grep -F 'deploy/northstar-entrypoint.sh /usr/local/bin/northstar-entrypoint' Dockerfile >/dev/null
grep -F 'ENTRYPOINT ["/usr/local/bin/northstar-entrypoint"]' Dockerfile >/dev/null
grep -F 'CMD ["/usr/local/bin/xmpp-server"]' Dockerfile >/dev/null
grep -F 'mkdir -p /opt/northstar /opt/deploy/postgres-init/lib /uploads /rollback /state /scratch' deploy/backup.Dockerfile >/dev/null
grep -F "northstar-upload-root-v1' > /data/uploads/.northstar-upload-root" Dockerfile >/dev/null
grep -F "northstar-upload-root-v1' > /uploads/.northstar-upload-root" deploy/backup.Dockerfile >/dev/null
grep -F "northstar-restore-rollback-v1' > /rollback/.northstar-rollback-root" deploy/backup.Dockerfile >/dev/null
grep -F -- '- restore-rollback:/rollback' docker-compose.yml >/dev/null
grep -Fx '  restore-rollback:' docker-compose.yml >/dev/null
grep -Fx 'umask 077' start_server.sh >/dev/null
grep -Fx 'umask 077' build_and_start.sh >/dev/null
grep -F 'driver: local' docker-compose.yml >/dev/null
grep -F 'max-size: "${DOCKER_LOG_MAX_SIZE:-10m}"' docker-compose.yml >/dev/null
grep -F 'max-file: "${DOCKER_LOG_MAX_FILES:-5}"' docker-compose.yml >/dev/null
[ "$(grep -c 'logging: \*bounded-logging' docker-compose.yml)" -eq 9 ] \
    || { echo "every Compose service must use bounded container logging" >&2; exit 1; }

test_root=$(mktemp -d "${TMPDIR:-/tmp}/northstar-log-security.XXXXXX")
cleanup() {
    status=$?
    trap - EXIT INT TERM
    case "$test_root" in
        "${TMPDIR:-/tmp}"/northstar-log-security.*) rm -rf -- "$test_root" ;;
        *) echo "refusing to remove unexpected log-security fixture" >&2; status=1 ;;
    esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$test_root/uploads" "$test_root/logs"
mkdir "$test_root/bin"
printf '%s\n' '#!/bin/sh' ': >"$NORTHSTAR_UMASK_PROBE"' >"$test_root/bin/cargo"
chmod 0755 "$test_root/bin/cargo"

# Exercise the development wrappers from a checkout-like fixture. A real .env
# is deliberately untracked, so running the repository copies directly makes
# this regression test depend on developer state and fail on a fresh CI runner.
# Keep the production guard intact and satisfy it only inside this disposable
# project; the fake cargo command below observes the wrappers' umask.
wrapper_project="$test_root/wrapper-project"
mkdir "$wrapper_project"
cp start_server.sh build_and_start.sh "$wrapper_project/"
: >"$wrapper_project/.env"
NORTHSTAR_UMASK_PROBE="$test_root/start-server-created.log" \
    PATH="$test_root/bin:$PATH" sh "$wrapper_project/start_server.sh" >/dev/null
NORTHSTAR_UMASK_PROBE="$test_root/build-and-start-created.log" \
    PATH="$test_root/bin:$PATH" sh "$wrapper_project/build_and_start.sh" >/dev/null
[ "$(stat -c '%a' "$test_root/start-server-created.log")" = 600 ]
[ "$(stat -c '%a' "$test_root/build-and-start-created.log")" = 600 ]
chmod 0755 "$test_root/uploads" "$test_root/logs"
: >"$test_root/logs/server.log.old"
chmod 0644 "$test_root/logs/server.log.old"
UPLOAD_DIR="$test_root/uploads" LOG_DIR="$test_root/logs" \
    sh deploy/northstar-entrypoint.sh sh -c \
    ': >"$LOG_DIR/server.log.new"; : >"$UPLOAD_DIR/private.part"'

[ "$(stat -c '%a' "$test_root/uploads")" = 700 ]
[ "$(stat -c '%a' "$test_root/logs")" = 700 ]
[ "$(stat -c '%a' "$test_root/uploads/.northstar-upload-root")" = 600 ]
[ "$(wc -c <"$test_root/uploads/.northstar-upload-root" | tr -d ' ')" = 25 ]
[ "$(cat "$test_root/uploads/.northstar-upload-root")" = northstar-upload-root-v1 ]
[ "$(stat -c '%a' "$test_root/logs/server.log.old")" = 600 ]
[ "$(stat -c '%a' "$test_root/logs/server.log.new")" = 600 ]
[ "$(stat -c '%a' "$test_root/uploads/private.part")" = 600 ]
UPLOAD_DIR="$test_root/uploads" LOG_DIR="$test_root/logs" \
    sh deploy/northstar-entrypoint.sh true

legacy_uploads="$test_root/legacy-uploads"
legacy_logs="$test_root/legacy-logs"
mkdir "$legacy_uploads" "$legacy_logs"
legacy_id=01234567-89ab-cdef-0123-456789abcdef
printf '%s' legacy-object >"$legacy_uploads/$legacy_id"
chmod 0644 "$legacy_uploads/$legacy_id"
UPLOAD_DIR="$legacy_uploads" LOG_DIR="$legacy_logs" \
    sh deploy/northstar-entrypoint.sh true
[ "$(cat "$legacy_uploads/.northstar-upload-root")" = northstar-upload-root-v1 ]
[ "$(stat -c '%a' "$legacy_uploads/.northstar-upload-root")" = 600 ]
[ "$(stat -c '%a' "$legacy_uploads/$legacy_id")" = 600 ]

foreign_uploads="$test_root/foreign-uploads"
foreign_logs="$test_root/foreign-logs"
mkdir "$foreign_uploads" "$foreign_logs"
printf '%s' operator-data >"$foreign_uploads/notes.txt"
if UPLOAD_DIR="$foreign_uploads" LOG_DIR="$foreign_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a foreign upload-root object" >&2
    exit 1
fi
[ "$(cat "$foreign_uploads/notes.txt")" = operator-data ]
[ ! -e "$foreign_uploads/.northstar-upload-root" ]

directory_uploads="$test_root/directory-object-uploads"
directory_logs="$test_root/directory-object-logs"
mkdir "$directory_uploads" "$directory_logs" "$directory_uploads/$legacy_id"
if UPLOAD_DIR="$directory_uploads" LOG_DIR="$directory_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a directory in an unmarked upload root" >&2
    exit 1
fi
[ -d "$directory_uploads/$legacy_id" ]
[ ! -e "$directory_uploads/.northstar-upload-root" ]

linked_uploads="$test_root/linked-object-uploads"
linked_logs="$test_root/linked-object-logs"
linked_target="$test_root/linked-object-target"
mkdir "$linked_uploads" "$linked_logs"
printf '%s' outside >"$linked_target"
ln -s "$linked_target" "$linked_uploads/$legacy_id"
if UPLOAD_DIR="$linked_uploads" LOG_DIR="$linked_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a linked upload object" >&2
    exit 1
fi
[ "$(cat "$linked_target")" = outside ]
[ ! -e "$linked_uploads/.northstar-upload-root" ]

bad_marker_uploads="$test_root/bad-marker-uploads"
bad_marker_logs="$test_root/bad-marker-logs"
mkdir "$bad_marker_uploads" "$bad_marker_logs"
printf '%s\n' wrong >"$bad_marker_uploads/.northstar-upload-root"
chmod 0600 "$bad_marker_uploads/.northstar-upload-root"
if UPLOAD_DIR="$bad_marker_uploads" LOG_DIR="$bad_marker_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a malformed existing upload-root marker" >&2
    exit 1
fi
[ "$(cat "$bad_marker_uploads/.northstar-upload-root")" = wrong ]

bad_mode_uploads="$test_root/bad-mode-marker-uploads"
bad_mode_logs="$test_root/bad-mode-marker-logs"
mkdir "$bad_mode_uploads" "$bad_mode_logs"
printf '%s\n' northstar-upload-root-v1 >"$bad_mode_uploads/.northstar-upload-root"
chmod 0644 "$bad_mode_uploads/.northstar-upload-root"
if UPLOAD_DIR="$bad_mode_uploads" LOG_DIR="$bad_mode_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a public existing upload-root marker" >&2
    exit 1
fi
[ "$(stat -c '%a' "$bad_mode_uploads/.northstar-upload-root")" = 644 ]

linked_marker_uploads="$test_root/linked-marker-uploads"
linked_marker_logs="$test_root/linked-marker-logs"
linked_marker_target="$test_root/linked-marker-target"
mkdir "$linked_marker_uploads" "$linked_marker_logs"
printf '%s\n' northstar-upload-root-v1 >"$linked_marker_target"
chmod 0600 "$linked_marker_target"
ln -s "$linked_marker_target" "$linked_marker_uploads/.northstar-upload-root"
if UPLOAD_DIR="$linked_marker_uploads" LOG_DIR="$linked_marker_logs" \
    sh deploy/northstar-entrypoint.sh true >/dev/null 2>&1; then
    echo "entrypoint accepted a linked upload-root marker" >&2
    exit 1
fi
[ "$(cat "$linked_marker_target")" = northstar-upload-root-v1 ]

echo "log security: private directories/files and bounded Compose logging passed"
