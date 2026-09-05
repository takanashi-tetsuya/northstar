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
  local record="$1" purpose address port
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
  done <<<"$record"
}

# Sets FIXTURE_READINESS_OUTPUT.  Callers intentionally do not wrap this in
# command substitution: registration must mutate the parent fixture's port
# ledger rather than a transient subshell copy.
fixture_wait_for_readiness() {
  local project_dir="$1" record_path="$2" nonce="$3" pid="$4"
  FIXTURE_READINESS_OUTPUT="$(python3 "$project_dir/scripts/wait-test-readiness.py" "$record_path" "$nonce" "$pid" 15)" || return 1
  fixture_register_readiness_ports "$FIXTURE_READINESS_OUTPUT"
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
