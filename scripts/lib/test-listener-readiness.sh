#!/usr/bin/env bash
# Shared shell helpers for child-owned Northstar fixture listeners.
#
# A fixture must never probe a TCP port, close it, and later ask a child to
# bind that number.  Instead the child binds 127.0.0.1:0 itself and publishes
# its actual addresses in a nonce- and PID-bound readiness record.  The parent
# records every address so cleanup can verify that no fixture listener leaked.

# The sourcing fixture owns this array deliberately.  It must be declared
# before calling any helper below:
#
#   declare -a fixture_listener_ports=()

fixture_readiness_port() {
  local record="$1" purpose="$2" address
  address="$(awk -F= -v purpose="$purpose" '$1 == purpose { print $2; exit }' <<<"$record")"
  [[ -n "$address" ]] || {
    echo "test readiness did not publish listener purpose $purpose" >&2
    return 1
  }
  local port="${address##*:}"
  [[ "$port" =~ ^[1-9][0-9]*$ ]] && ((port <= 65535)) || {
    echo "test readiness published an invalid address for $purpose: $address" >&2
    return 1
  }
  printf '%s' "$port"
}

fixture_register_readiness_ports() {
  # ``owner_pid`` is optional so existing standalone fixtures retain their
  # lightweight port-only cleanup.  The MIX matrix declares the two
  # associative ledgers below and upgrades each port to its exact owner
  # identity before the parent later verifies socket inodes after quiescence.
  local record="$1" owner_pid="${2:-}" purpose address port
  declare -p fixture_listener_ports >/dev/null 2>&1 || {
    echo "fixture_listener_ports must be declared by the parent fixture" >&2
    return 1
  }
  while IFS='=' read -r purpose address; do
    [[ -n "$purpose" && -n "$address" ]] || continue
    port="${address##*:}"
    [[ "$port" =~ ^[1-9][0-9]*$ ]] && ((port <= 65535)) || {
      echo "invalid listener address in readiness record: $address" >&2
      return 1
    }
    fixture_listener_ports+=("$port")
    if [[ -n "$owner_pid" ]]; then
      [[ "$owner_pid" =~ ^[1-9][0-9]*$ ]] || {
        echo "invalid listener owner PID in readiness registration: $owner_pid" >&2
        return 1
      }
      if declare -p fixture_listener_owner_pids >/dev/null 2>&1; then
        fixture_listener_owner_pids["$port"]="$owner_pid"
      fi
      if declare -p fixture_listener_purposes >/dev/null 2>&1; then
        fixture_listener_purposes["$port"]="$purpose"
      fi
    fi
  done <<<"$record"
}

# Sets FIXTURE_READINESS_OUTPUT.  Callers intentionally do not wrap this in
# command substitution: registration must mutate the parent fixture's port
# ledger rather than a transient subshell copy.
fixture_wait_for_readiness() {
  local project_dir="$1" record_path="$2" nonce="$3" pid="$4"
  local -a arguments=("$record_path" "$nonce" "$pid" 15)
  [[ -z "${5:-}" ]] || arguments+=(--deadline "$5")
  FIXTURE_READINESS_OUTPUT="$(python3 "$project_dir/scripts/wait-test-readiness.py" "${arguments[@]}")" || return 1
  fixture_register_readiness_ports "$FIXTURE_READINESS_OUTPUT" "$pid"
}

# The caller obtains this before spawning the server, then gives the same
# absolute monotonic deadline to both socket ownership and HTTP health checks.
fixture_startup_deadline() {
  python3 "$1/scripts/wait-test-readiness.py" --startup-deadline
}

fixture_wait_for_http_readiness() {
  local project_dir="$1"
  shift
  python3 "$project_dir/scripts/wait-test-readiness.py" --http-ready "$@"
}

# Certificates, binary/database preparation and child-owned relay readiness
# all precede Northstar cold start. Every pair finishes those steps before any
# server starts its bounded startup/heartbeat clocks. Standalone runs are a no-op.
fixture_stress_phase_barrier() {
  local project_dir="$1" phase="$2"
  if [[ -z "${NORTHSTAR_LISTENER_STRESS_PHASE_DIR:-}" ]]; then
    [[ -z "${NORTHSTAR_LISTENER_STRESS_PHASE_NONCE:-}" \
       && -z "${NORTHSTAR_LISTENER_STRESS_PHASE_ROUND:-}" \
       && -z "${NORTHSTAR_LISTENER_STRESS_PHASE_PAIR:-}" ]] || {
      echo "listener stress phase configuration must be set together" >&2
      return 1
    }
    return 0
  fi
  python3 "$project_dir/scripts/listener-stress-phases.py" worker \
    "$NORTHSTAR_LISTENER_STRESS_PHASE_DIR" \
    "${NORTHSTAR_LISTENER_STRESS_PHASE_NONCE:?missing phase nonce}" \
    "${NORTHSTAR_LISTENER_STRESS_PHASE_ROUND:?missing phase round}" \
    "$phase" "${NORTHSTAR_LISTENER_STRESS_PHASE_PAIR:?missing phase pair}" \
    "${NORTHSTAR_CI_COMMAND_TIMEOUT_SECONDS:-900}"
}

fixture_port_is_listening() {
  local port="$1"
  ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .
}

fixture_assert_no_listeners() {
  local port leaked=0
  for port in "${fixture_listener_ports[@]}"; do
    if fixture_port_is_listening "$port"; then
      echo "fixture listener remained on port $port" >&2
      leaked=1
    fi
  done
  ((leaked == 0))
}

# A dynamic backend port is not a substitute for a correct public endpoint.
# Verify the server's own public configuration through the stable fixture
# relay, so a runtime suite cannot silently advertise a default 80/443 URL
# while its real test traffic bypasses that authority.
fixture_assert_public_url() {
  local port="$1" expected="$2" observed
  if ! observed="$(curl --silent --fail "http://127.0.0.1:$port/api/v1/config" \
    | python3 -c 'import json, sys; value = json.load(sys.stdin).get("public_url"); print(value if isinstance(value, str) else "")')"; then
    echo "fixture could not read public_url through relay port $port" >&2
    return 1
  fi
  if [[ "$observed" != "$expected" ]]; then
    echo "fixture advertised public_url $observed, expected $expected" >&2
    return 1
  fi
}

# Publish a complete relay target in one rename operation.  The relay may be
# accepting a connection while a server generation hands off its dynamic
# backend port, so writing directly to the final file would allow it to parse
# a transient partial HOST:PORT record.  The temporary lives beside the final
# target to preserve same-filesystem rename atomicity.
fixture_publish_relay_target() {
  local target="$1" port="$2" temporary
  [[ "$port" =~ ^[1-9][0-9]*$ ]] && ((port <= 65535)) || {
    echo "refusing invalid relay target port: $port" >&2
    return 1
  }
  temporary="$(mktemp "${target}.tmp.XXXXXX")" || return 1
  if ! printf '127.0.0.1:%s\n' "$port" >"$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! chmod 600 "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -f -- "$temporary" "$target"; then
    rm -f -- "$temporary"
    return 1
  fi
}

# Starts a child-owned TCP relay used only when a two-node fixture must know a
# peer endpoint before either Northstar process can publish its own readiness
# record.  The relay itself uses the same authenticated readiness contract and
# forwards to the target address written by the server-owning child later.
#
# Arguments: project runtime label purpose target-file log-file pid-variable
#            port-variable
fixture_start_tcp_relay() {
  local project_dir="$1" runtime_dir="$2" label="$3" purpose="$4"
  local target_file="$5" log_file="$6" pid_variable="$7" port_variable="$8"
  local readiness_file="$runtime_dir/$label.relay.ready.json"
  local readiness_nonce
  readiness_nonce="$(openssl rand -hex 16)"
  rm -f -- "$readiness_file"
  python3 "$project_dir/scripts/test-listener-relay.py" \
    --readiness-file "$readiness_file" \
    --nonce "$readiness_nonce" \
    --purpose "$purpose" \
    --target-file "$target_file" >"$log_file" 2>&1 &
  local relay_pid=$!
  if ! fixture_wait_for_readiness "$project_dir" "$readiness_file" "$readiness_nonce" "$relay_pid"; then
    kill "$relay_pid" 2>/dev/null || true
    wait "$relay_pid" 2>/dev/null || true
    return 1
  fi
  local relay_port
  relay_port="$(fixture_readiness_port "$FIXTURE_READINESS_OUTPUT" "$purpose")" || return 1
  printf -v "$pid_variable" '%s' "$relay_pid"
  printf -v "$port_variable" '%s' "$relay_port"
}
