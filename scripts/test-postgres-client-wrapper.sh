#!/usr/bin/env bash
set -Eeuo pipefail
set +x

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
runtime_dir="$(mktemp -d "${TMPDIR:-/tmp}/northstar-pg-client-wrapper.XXXXXX")"
cleanup() {
  case "$runtime_dir" in
    "${TMPDIR:-/tmp}"/northstar-pg-client-wrapper.*) rm -rf -- "$runtime_dir" ;;
    *) printf 'refusing unexpected wrapper-test cleanup path: %s\n' "$runtime_dir" >&2 ;;
  esac
}
trap cleanup EXIT

cat >"$runtime_dir/probe.py" <<'PY'
import os
from pathlib import Path
import re
import stat

passfile = os.environ.get("PGPASSFILE", "")
assert re.fullmatch(r"/proc/self/fd/[0-9]+", passfile), passfile
metadata = os.stat(passfile)
assert stat.S_ISREG(metadata.st_mode)
assert stat.S_IMODE(metadata.st_mode) == 0o600
assert Path(passfile).read_text(encoding="utf-8") == "*:*:*:*:p\\:a\\\\ss\n"
assert "DATABASE_URL" not in os.environ
assert "DATABASE_URL_FILE" not in os.environ
assert "PGPASSWORD" not in os.environ
assert os.environ["PGUSER"] == "northstar_test"
assert os.environ["PGHOST"] == "localhost"
assert os.environ["PGDATABASE"] == "northstar_test"
print(os.getpid())
PY

output="$runtime_dir/pid"
DATABASE_URL='postgresql://northstar_test:p%3Aa%5Css@localhost/northstar_test' \
PGPASSWORD='must-not-survive-exec' \
  python3 "$project_dir/scripts/run-postgres.py" -- \
    python3 "$runtime_dir/probe.py" >"$output" &
registered_pid=$!
wait "$registered_pid"
observed_pid="$(sed -n '1p' "$output")"
[[ "$observed_pid" =~ ^[0-9]+$ && "$observed_pid" == "$registered_pid" ]] \
  || { printf 'wrapper did not exec in place: registered=%s observed=%s\n' \
       "$registered_pid" "$observed_pid" >&2; exit 1; }

printf '%s\n' 'PostgreSQL client wrapper exact-PID and memory-only credential test passed'
