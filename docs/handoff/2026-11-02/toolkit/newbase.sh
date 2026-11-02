#!/usr/bin/env bash
# Usage: newbase.sh [commit]: records the test names and gate results of a commit (default HEAD) as the baseline that
# verify.sh compares with. Run it at the start of a session, before the first edit, and again after a rebase.
. "$(dirname "$0")/common.sh"
sha=$(git -C "$ROOT" rev-parse "${1:-HEAD}^{commit}") || exit 1
W=$ROOT
if [ "$sha" != "$(git -C "$ROOT" rev-parse HEAD)" ] || [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
  W=$BASE/tree
  git -C "$ROOT" worktree remove --force "$W" 2> /dev/null
  git -C "$ROOT" worktree prune
  git -C "$ROOT" worktree add -q --detach "$W" "$sha" || exit 1
fi
bash "$TK/listtests.sh" "$W" "$BASE/ws" || exit 1
bash "$TK/gates.sh" "$W" > "$BASE/gates.base" 2>&1
echo "$sha" > "$BASE/rev"
echo "base done at $sha"
