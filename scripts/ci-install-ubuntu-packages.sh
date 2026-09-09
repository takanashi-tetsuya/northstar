#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted runners include optional third-party APT sources (notably the
# Chrome repository). Northstar's CI only needs Ubuntu-packaged tools, so a
# transient third-party metadata failure must not make an unrelated database
# or protocol job fail before it starts. Fail closed if the pinned runner
# source manifest is absent; silently falling back to every configured source
# would reintroduce the non-deterministic dependency.
if (( $# == 0 )); then
  echo "usage: $0 <ubuntu-package> [...]" >&2
  exit 2
fi

readonly ubuntu_sources="/etc/apt/sources.list.d/ubuntu.sources"
if [[ ! -r "$ubuntu_sources" ]]; then
  echo "CI requires the GitHub Ubuntu source manifest at $ubuntu_sources" >&2
  exit 2
fi

readonly -a ubuntu_apt=(
  sudo apt-get
  -o "Dir::Etc::sourcelist=sources.list.d/ubuntu.sources"
  -o "Dir::Etc::sourceparts=-"
)

"${ubuntu_apt[@]}" update
"${ubuntu_apt[@]}" install --yes --no-install-recommends "$@"
