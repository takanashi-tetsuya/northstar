#!/usr/bin/env bash
# Shared profile selection for the two real federation fixtures. A stress
# parent selects runtime-test explicitly; ordinary direct runs retain dev.
fixture_select_runtime_profile() {
  fixture_cargo_profile="${1:-dev}"
  case "$fixture_cargo_profile" in
    dev) fixture_cargo_profile_directory=debug ;;
    runtime-test) fixture_cargo_profile_directory=runtime-test ;;
    *) echo "runtime fixture profile must be dev or runtime-test" >&2; return 2 ;;
  esac
}
