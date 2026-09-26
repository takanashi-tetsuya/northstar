#!/usr/bin/env bash
set -euo pipefail

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }

network_xml=$(virsh net-dumpxml northstar-lab)
if [[ $network_xml == *'<forward'* ]]; then
  echo 'lab network has a forwarding rule' >&2
  exit 1
fi

for guest in ns-a ns-b prosody ejabberd infra dns-ca; do
  vm=northstar-lab-$guest
  [[ $(virsh domstate "$vm") == running ]] || {
    echo "VM is not running: $vm" >&2
    exit 1
  }
  if virsh domiflist "$vm" | awk '$2 == "network" && $3 != "northstar-lab" { bad = 1 } END { exit !bad }'; then
    echo "VM has a non-lab interface: $vm" >&2
    exit 1
  fi
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || {
    echo "no private DHCP address for $vm" >&2
    exit 1
  }
  ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$(dirname "$key")/known_hosts" \
    "lab@$ip" 'cloud-init status --wait >/dev/null; test -z "$(ip -4 route show default)"; test -z "$(ip -6 route show default)"'
  echo "$vm $ip isolated"
done
