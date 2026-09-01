#!/bin/sh
set -eu
set +x

# Keep both freshly created rolling logs and upload staging files private even
# when the host/container default umask is permissive.
umask 077

upload_dir=${UPLOAD_DIR:-/data/uploads}
log_dir=${LOG_DIR:-/data/logs}
for directory in "$upload_dir" "$log_dir"; do
    [ "$directory" != / ] \
        || { echo "refusing a broad Northstar writable directory" >&2; exit 1; }
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        || { echo "Northstar writable directory is absent or linked: $directory" >&2; exit 1; }
done

upload_marker="$upload_dir/.northstar-upload-root"
upload_owner=$(stat -c %u:%g "$upload_dir")
is_upload_uuid() (
    candidate=$1
    case "$candidate" in
        ????????-????-????-????-????????????) ;;
        *) exit 1 ;;
    esac
    IFS=-
    set -- $candidate
    [ "$#" -eq 5 ] || exit 1
    case "$1$2$3$4$5" in
        *[!0-9a-f]*) exit 1 ;;
        *) exit 0 ;;
    esac
)

# A legacy named volume may predate the ownership marker.  Inspect the entire
# flat namespace before changing anything: only final lower-case UUID objects
# can be upgraded automatically.  Links, partials, directories and operator
# files fail closed so startup cannot bless the wrong mount as upload storage.
marker_present=false
if [ -e "$upload_marker" ] || [ -L "$upload_marker" ]; then
    [ -f "$upload_marker" ] && [ ! -L "$upload_marker" ] \
        || { echo "upload-root marker is not a regular file" >&2; exit 1; }
    [ "$(stat -c %a "$upload_marker")" = 600 ] \
        || { echo "upload-root marker must be mode 0600" >&2; exit 1; }
    [ "$(stat -c %u:%g "$upload_marker")" = "$upload_owner" ] \
        || { echo "upload-root marker ownership differs from its root" >&2; exit 1; }
    [ "$(wc -c <"$upload_marker" | tr -d ' ')" = 25 ] \
        && [ "$(cat "$upload_marker")" = northstar-upload-root-v1 ] \
        || { echo "upload-root marker has unexpected content" >&2; exit 1; }
    marker_present=true
else
    for entry in "$upload_dir"/* "$upload_dir"/.[!.]* "$upload_dir"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        name=${entry##*/}
        if is_upload_uuid "$name" && [ -f "$entry" ] && [ ! -L "$entry" ] \
           && [ "$(stat -c %u:%g "$entry")" = "$upload_owner" ]; then
            :
        else
            echo "unmarked upload root contains an unexpected object: $name" >&2
            exit 1
        fi
    done
fi

chmod 0700 "$upload_dir" "$log_dir"
for entry in "$upload_dir"/*; do
    [ -e "$entry" ] || continue
    name=${entry##*/}
    if is_upload_uuid "$name" && [ -f "$entry" ] && [ ! -L "$entry" ]; then
        chmod 0600 "$entry"
    fi
done

if [ "$marker_present" = false ]; then
    marker_temporary=$(mktemp "$upload_dir/.northstar-upload-root.XXXXXX")
    printf '%s\n' northstar-upload-root-v1 >"$marker_temporary"
    chmod 0600 "$marker_temporary"
    if ! ln "$marker_temporary" "$upload_marker"; then
        rm -f -- "$marker_temporary"
        echo "could not atomically establish the upload-root marker" >&2
        exit 1
    fi
    rm -f -- "$marker_temporary"
fi

# Upgrade files created by older images with a permissive umask. Restrict the
# known flat rolling-log namespace without traversing operator-owned trees or
# following symlinks.
find "$log_dir" -mindepth 1 -maxdepth 1 -type f -name 'server.log*' \
    -exec chmod 0600 {} \;

exec "$@"
