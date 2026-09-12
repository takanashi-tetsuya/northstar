#!/usr/bin/env bash
# Build ordinary-user PostgreSQL test tools, never a system service.
set -euo pipefail
[[ $# == 1 && "$1" == /* ]] || { echo 'usage: ci-postgres17-tools.sh /absolute/prefix' >&2; exit 2; }
readonly prefix="$1"
readonly version=17.11
readonly source_sha=dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979
if [[ -r "$prefix/.source-sha256" && "$(<"$prefix/.source-sha256")" == "$source_sha" ]] \
   && [[ -x "$prefix/bin/postgres" && -f "$prefix/lib/libpq.so.5" ]] \
   && [[ "$("$prefix/bin/postgres" --version)" == "postgres (PostgreSQL) $version" ]]; then
  echo "PostgreSQL $version test tools restored"
  exit 0
fi
build_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/northstar-pg17-build.XXXXXXXX")"
trap 'rm -rf -- "$build_dir"' EXIT
curl --fail --location --retry 2 --connect-timeout 15 --max-time 120 \
  "https://ftp.postgresql.org/pub/source/v$version/postgresql-$version.tar.bz2" \
  --output "$build_dir/source.tar.bz2"
printf '%s  %s\n' "$source_sha" "$build_dir/source.tar.bz2" | sha256sum --check --status
tar -xjf "$build_dir/source.tar.bz2" -C "$build_dir"
cd "$build_dir/postgresql-$version"
./configure --prefix="$prefix" --without-readline --without-zlib --without-icu
build_jobs="$(nproc)"
((build_jobs <= 4)) || build_jobs=4
make -j "$build_jobs"
make install
printf '%s\n' "$source_sha" >"$prefix/.source-sha256"
"$prefix/bin/postgres" --version
