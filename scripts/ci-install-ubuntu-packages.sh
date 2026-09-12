#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted runners include optional third-party APT sources (notably the
# Chrome repository). Northstar's CI only needs Ubuntu-packaged tools, so a
# transient third-party metadata failure must not make an unrelated database
# or protocol job fail before it starts. Ubuntu 22.04 uses sources.list;
# newer runners use the deb822 ubuntu.sources file. Fail closed if neither
# Ubuntu manifest is present; falling back to every configured source
# would reintroduce the non-deterministic dependency.
if (( $# == 0 )); then
  echo "usage: $0 <ubuntu-package> [...]" >&2
  exit 2
fi

ubuntu_sources="sources.list.d/ubuntu.sources"
if [[ ! -r "/etc/apt/$ubuntu_sources" ]]; then
  ubuntu_sources="sources.list"
fi
readonly ubuntu_sources
if [[ ! -r "/etc/apt/$ubuntu_sources" ]]; then
  echo "CI requires the GitHub Ubuntu sources.list or ubuntu.sources manifest" >&2
  exit 2
fi

readonly -a ubuntu_apt=(
  sudo apt-get
  -o "Dir::Etc::sourcelist=$ubuntu_sources"
  -o "Dir::Etc::sourceparts=-"
)

"${ubuntu_apt[@]}" update
"${ubuntu_apt[@]}" install --yes --no-install-recommends "$@"
