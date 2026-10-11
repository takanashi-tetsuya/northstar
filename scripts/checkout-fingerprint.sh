#!/usr/bin/env bash
# An editing agent's file tools are not confined to its worktree, so the architecture lead
# fingerprints every checkout before and after each run and compares.
# Usage: scripts/checkout-fingerprint.sh [--exclude <path>]...
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

EXCLUDES=()
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--exclude" ]]; then
    if [[ $# -lt 2 ]]; then
      echo "Usage: scripts/checkout-fingerprint.sh [--exclude <path>]..." >&2
      exit 2
    fi
    EXCLUDES+=("$(realpath -m "$2")")
    shift 2
  else
    echo "Usage: scripts/checkout-fingerprint.sh [--exclude <path>]..." >&2
    exit 2
  fi
done

is_excluded() {
  local path="$1"
  for ex in "${EXCLUDES[@]}"; do
    if [[ "$path" == "$ex" ]]; then
      return 0
    fi
  done
  return 1
}

git -C "$REPO_DIR" worktree list --porcelain | while read -r line; do
  if [[ "$line" == worktree\ * ]]; then
    o="${line#worktree }"
    if is_excluded "$o"; then
      continue
    fi
    if [[ ! -d "$o" ]]; then
      echo "$o missing"
      continue
    fi
    d=$(git -C "$o" diff HEAD | sha1sum | cut -c1-12)
    u=$(git -C "$o" ls-files --others --exclude-standard -z | (cd "$o" && xargs -0 -r sha1sum) | sha1sum | cut -c1-12)
    echo "$o diff=$d untracked=$u"
  fi
done
