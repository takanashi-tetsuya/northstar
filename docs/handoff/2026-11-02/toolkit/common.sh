# Sourced by the other scripts. Baselines and logs stay outside the checkout so they never reach a commit.
TK=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(git -C "$TK" rev-parse --show-toplevel)
BASE=${NORTHSTAR_BASE:-$HOME/.cache/northstar/base}
RUNS=${NORTHSTAR_RUNS:-$HOME/.cache/northstar/runs}
mkdir -p "$BASE" "$RUNS"
