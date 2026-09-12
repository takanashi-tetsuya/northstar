#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
exec bash "${repository_root}/scripts/resolve-contract-baseline.sh" --self-test
