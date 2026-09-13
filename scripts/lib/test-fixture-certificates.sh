#!/usr/bin/env bash
fixture_certificates_restore() {
  fixture_certificates_reused=false
  [[ -n "${NORTHSTAR_LISTENER_STRESS_CERTIFICATE_CACHE:-}" ]] || return 0
  local status=0
  python3 "$project_dir/scripts/fixture-certificate-cache.py" restore \
    --cache "$NORTHSTAR_LISTENER_STRESS_CERTIFICATE_CACHE" --output "$2" --fixture "$1" \
    --scope "${NORTHSTAR_LISTENER_STRESS_CERTIFICATE_SCOPE:-}" || status=$?
  case "$status" in
    0) fixture_certificates_reused=true ;;
    3) ;;
    *) return "$status" ;;
  esac
}

fixture_certificates_save() {
  [[ -n "${NORTHSTAR_LISTENER_STRESS_CERTIFICATE_CACHE:-}" && "$fixture_certificates_reused" == false ]] || return 0
  python3 "$project_dir/scripts/fixture-certificate-cache.py" save \
    --cache "$NORTHSTAR_LISTENER_STRESS_CERTIFICATE_CACHE" --output "$2" --fixture "$1" \
    --scope "${NORTHSTAR_LISTENER_STRESS_CERTIFICATE_SCOPE:-}"
}
