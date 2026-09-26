#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 FIXTURE_DIR BIND_IP PORT TLS_VERSION RESPONSE" >&2
  echo "TLS_VERSION: 1.2 or 1.3; RESPONSE: good, revoked, stale, missing, wrong-leaf, wrong-issuer" >&2
  exit 2
fi

fixture_dir=$1
bind_ip=$2
port=$3
version=$4
response=$5

python3 - "$bind_ip" "$port" "$fixture_dir" <<'PY'
import ipaddress
import os
from pathlib import Path
import stat
import sys

address = ipaddress.ip_address(sys.argv[1])
port = int(sys.argv[2])
fixture = Path(sys.argv[3])
lab_network = ipaddress.ip_network("192.168.197.0/24")
if (
    address.version != 4
    or not (address.is_loopback or address in lab_network)
    or not 1024 <= port <= 65535
):
    raise SystemExit("peer needs a loopback/lab IPv4 address and unprivileged port")
try:
    directory_stat = fixture.lstat()
    key_stat = (fixture / "leaf.key").lstat()
except OSError as error:
    raise SystemExit(f"cannot inspect OCSP fixture: {error}") from error
if (
    not stat.S_ISDIR(directory_stat.st_mode)
    or directory_stat.st_uid != os.geteuid()
    or stat.S_IMODE(directory_stat.st_mode) != 0o700
    or not stat.S_ISREG(key_stat.st_mode)
    or key_stat.st_uid != os.geteuid()
    or stat.S_IMODE(key_stat.st_mode) != 0o600
):
    raise SystemExit("OCSP fixture must be a current-user 0700 directory with a 0600 regular leaf.key")
PY

case $version in
  1.2) version_option=-tls1_2 ;;
  1.3) version_option=-tls1_3 ;;
  *) echo "TLS_VERSION must be 1.2 or 1.3" >&2; exit 2 ;;
esac
case $response in
  good|revoked|stale|wrong-leaf|wrong-issuer)
    response_option=(-status_file "$fixture_dir/$response.der") ;;
  missing) response_option=() ;;
  *) echo "unsupported OCSP response" >&2; exit 2 ;;
esac

for file in leaf.crt leaf.key root.crt SHA256SUMS; do
  [[ -f $fixture_dir/$file ]] || {
    echo "missing fixture file: $file" >&2
    exit 2
  }
done
(cd "$fixture_dir" && sha256sum -c --status SHA256SUMS)

# Bind only to the explicit loopback or isolated-lab address. A successful
# TLS handshake may be followed by an XMPP stream and then EOF; the caller
# should capture stdout/stderr and the Northstar dial result separately.
exec openssl s_server \
  -accept "$bind_ip:$port" \
  -cert "$fixture_dir/leaf.crt" -key "$fixture_dir/leaf.key" \
  -cert_chain "$fixture_dir/root.crt" \
  -alpn xmpp-server -no_ticket -naccept 1 \
  "$version_option" -status "${response_option[@]}" -quiet
