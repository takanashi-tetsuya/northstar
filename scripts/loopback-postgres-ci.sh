#!/usr/bin/env bash
set -euo pipefail

# Runtime fixtures deliberately use the single-owner development database
# escape hatch.  A normal GitHub Actions service container is reached through
# Docker's bridge, so PostgreSQL correctly reports a non-loopback server
# address even when the runner connects to a published 127.0.0.1 port.  Start
# the pinned fixture in the runner's network namespace instead, and constrain
# PostgreSQL itself to 127.0.0.1.  This preserves the production fail-closed
# attestation instead of teaching it to trust CI or Docker bridge addresses.

readonly container_name='northstar-ci-loopback-postgres'
readonly postgres_image='postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'

stop_fixture() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
}

if [[ "${1:-start}" == stop ]]; then
  stop_fixture
  exit 0
fi
if [[ "${1:-start}" != start || $# -gt 1 ]]; then
  echo 'usage: loopback-postgres-ci.sh [start|stop]' >&2
  exit 2
fi
if [[ "${CI:-}" != true || "${GITHUB_ACTIONS:-}" != true ]]; then
  echo 'the loopback PostgreSQL fixture is restricted to GitHub Actions CI' >&2
  exit 2
fi
if docker container inspect "$container_name" >/dev/null 2>&1; then
  echo "refusing to replace an existing container: $container_name" >&2
  exit 2
fi

fixture_ready=false
cleanup_failed_start() {
  if [[ "$fixture_ready" != true ]]; then
    docker logs "$container_name" >&2 2>/dev/null || true
    stop_fixture
  fi
}
trap cleanup_failed_start EXIT

docker run --detach \
  --name "$container_name" \
  --network host \
  --env POSTGRES_DB=xmpp_test \
  --env POSTGRES_USER=xmpp_test \
  --env POSTGRES_PASSWORD=xmpp-test-password \
  "$postgres_image" \
  -c listen_addresses=127.0.0.1 \
  -c password_encryption=scram-sha-256 >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$container_name" \
    pg_isready --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
    >/dev/null 2>&1; then
    server_address="$(docker exec \
      --env PGPASSWORD=xmpp-test-password \
      "$container_name" \
      psql --host 127.0.0.1 --username xmpp_test --dbname xmpp_test \
      --tuples-only --no-align --set ON_ERROR_STOP=1 \
      --command 'SELECT pg_catalog.host(pg_catalog.inet_server_addr())')"
    server_address="${server_address//[[:space:]]/}"
    if [[ "$server_address" != 127.0.0.1 ]]; then
      echo "PostgreSQL did not accept the fixture over loopback: $server_address" >&2
      exit 1
    fi
    fixture_ready=true
    break
  fi
  sleep 1
done

if [[ "$fixture_ready" != true ]]; then
  echo 'loopback PostgreSQL fixture did not become ready' >&2
  exit 1
fi

trap - EXIT
echo 'loopback PostgreSQL fixture ready on 127.0.0.1:5432'
