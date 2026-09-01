#!/usr/bin/env bash
set -euo pipefail

duration_seconds="${1:-30}"
if [[ ! "$duration_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "duration must be a positive integer" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
project_dir="$(cd -- "$script_dir/.." && pwd -P)"
nightly_toolchain="nightly-2026-08-25"
if [[ "${XMPP_TEST_SYSTEM_TOOLCHAIN:-false}" == "true" ]]; then
  echo "parser robustness requires the repository-pinned nightly-2026-08-25 toolchain and cargo-fuzz; unset XMPP_TEST_SYSTEM_TOOLCHAIN" >&2
  exit 2
fi
export PATH="$project_dir/.cargo-linux/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export RUSTUP_HOME="$project_dir/.rustup-linux"
export CARGO_HOME="$project_dir/.cargo-local"
pinned_toolchain="$RUSTUP_HOME/toolchains/${nightly_toolchain}-x86_64-unknown-linux-gnu"
[[ -x "$pinned_toolchain/bin/rustc" ]] || {
  echo "missing repository-pinned Rust toolchain: $pinned_toolchain" >&2
  exit 2
}
[[ -x "$project_dir/.cargo-linux/bin/cargo-fuzz" ]] || {
  echo "missing repository-pinned cargo-fuzz: $project_dir/.cargo-linux/bin/cargo-fuzz" >&2
  exit 2
}
run_root="$(mktemp -d /tmp/northstar-parser-robustness.XXXXXXXX)"
run_stamp="$(date -u +%Y%m%dT%H%M%SZ)"

cleanup() {
  local status=$?
  trap - EXIT
  if (( status != 0 )); then
    local evidence_dir="$project_dir/target/fuzz-artifacts/$run_stamp"
    mkdir -p -- "$evidence_dir"
    if [[ -d "$run_root/artifacts" ]]; then
      cp -a -- "$run_root/artifacts/." "$evidence_dir/"
    fi
    echo "parser robustness run failed; artifacts preserved at $evidence_dir" >&2
  fi
  case "$run_root" in
    /tmp/northstar-parser-robustness.*)
      rm -rf -- "$run_root"
      ;;
    *)
      echo "refusing to clean unexpected temporary path: $run_root" >&2
      status=1
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT

cd -- "$project_dir"
test -f fuzz/Cargo.toml
cargo +"$nightly_toolchain" fuzz --help >/dev/null

targets=(
  xml_framing
  semantic_stanza
  bosh_ws_framing
  rest_extractors
  sasl_sm_state
  mam_pubsub_parsing
)

for target in "${targets[@]}"; do
  corpus_dir="$run_root/corpus/$target"
  artifact_dir="$run_root/artifacts/$target"
  mkdir -p -- "$corpus_dir" "$artifact_dir"
  echo "TARGET_START $target"
  cargo +"$nightly_toolchain" fuzz run "$target" "$corpus_dir" -- \
    -max_total_time="$duration_seconds" \
    -timeout=5 \
    -rss_limit_mb=2048 \
    -artifact_prefix="$artifact_dir/" \
    -print_final_stats=1
  echo "TARGET_PASS $target"
done

echo "PARSER_ROBUSTNESS_PASS targets=${#targets[@]} duration_each=${duration_seconds}s"
