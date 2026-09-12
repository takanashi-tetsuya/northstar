#!/usr/bin/env bash
# Compare existing wire contracts, or compile a proven first introduction.
set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
resolution="$(bash "$script_dir/resolve-contract-baseline.sh")"
printf '%s\n' "$resolution"
baseline_sha="$(awk -F= '$1 == "baseline_sha" { print $2 }' <<<"$resolution")"
baseline_mode="$(awk -F= '$1 == "baseline_mode" { print $2 }' <<<"$resolution")"
buf --version

case "$baseline_mode" in
  existing)
    temp_branch="northstar-contract-baseline-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
    temp_ref="refs/heads/${temp_branch}"
    trap 'git update-ref -d "$temp_ref"' EXIT
    git update-ref "$temp_ref" "$baseline_sha"
    buf breaking contracts/proto --against ".git#branch=${temp_branch},subdir=contracts/proto"
    ;;
  initial)
    # Buf 1.50 rejects empty images. There are no earlier schema definitions;
    # compile the new module while the separate quality job enforces lint,
    # format and generated-code drift. The resolver proved complete history.
    printf 'Initial contract introduction: no prior Protobuf API at the baseline.\n'
    buf build contracts/proto --output /dev/null
    ;;
  *)
    printf 'Unsupported contract baseline mode: %s\n' "$baseline_mode" >&2
    exit 2
    ;;
esac
