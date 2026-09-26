#!/usr/bin/env bash
set -euo pipefail

network_name=northstar-lab

if virsh net-info "$network_name" >/dev/null 2>&1; then
  if ! virsh net-info "$network_name" | rg -q '^Active:[[:space:]]+yes$'; then
    virsh net-start "$network_name" >/dev/null
  fi
  virsh net-info "$network_name"
  exit 0
fi

network_xml=$(mktemp)
trap 'rm -f "$network_xml"' EXIT
cat >"$network_xml" <<'XML'
<network>
  <name>northstar-lab</name>
  <bridge name='virbr-nstar' stp='on' delay='0'/>
  <domain name='lab.test' localOnly='yes'/>
  <ip address='192.168.197.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.197.100' end='192.168.197.199'/>
    </dhcp>
  </ip>
  <ip family='ipv6' address='fd7a:6e73:7461:72::1' prefix='64'/>
</network>
XML

virsh net-define "$network_xml" >/dev/null
virsh net-start "$network_name" >/dev/null
virsh net-info "$network_name"
