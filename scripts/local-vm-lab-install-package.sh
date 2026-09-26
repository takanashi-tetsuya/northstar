#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
  echo "usage: $0 VM PRIVATE_IPV4 PACKAGE" >&2
  exit 2
fi

vm=$1
ip=$2
package=$3
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ $vm =~ ^northstar-lab-[a-z0-9-]+$ ]] || exit 2
[[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 2
[[ $package =~ ^[a-z0-9+.-]+$ ]] || exit 2
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }

ssh_lab=(ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts" "lab@$ip")

if virsh domiflist "$vm" | rg -q '[[:space:]]default[[:space:]]'; then
  echo 'VM already has a provisioning interface' >&2
  exit 1
fi

provision_mac=
cleanup() {
  result=$?
  trap - EXIT
  if [[ -n $provision_mac ]]; then
    if ! "${ssh_lab[@]}" 'sudo rm -f /run/systemd/network/99-northstar-provision.network; sudo networkctl reload; sudo networkctl reconfigure enp7s0' >/dev/null 2>&1; then
      echo 'could not remove temporary guest network configuration' >&2
      result=1
    fi
    if ! virsh detach-interface "$vm" network --mac "$provision_mac" --live >/dev/null; then
      echo 'temporary NAT interface is still attached' >&2
      result=1
    fi
  fi
  exit "$result"
}
trap cleanup EXIT

virsh attach-interface "$vm" network default --model virtio --live >/dev/null
provision_mac=$(virsh domiflist "$vm" | awk '$3 == "default" { print $5 }')
[[ -n $provision_mac ]] || { echo 'temporary interface not found' >&2; exit 1; }

"${ssh_lab[@]}" 'sudo tee /run/systemd/network/99-northstar-provision.network >/dev/null; sudo networkctl reload; sudo networkctl reconfigure enp7s0' <<'EOF'
[Match]
Name=enp7s0
[Network]
DHCP=ipv4
EOF

"${ssh_lab[@]}" 'for attempt in $(seq 1 30); do if ip -4 route show default | grep -q "via 192.168.122.1"; then exit 0; fi; sleep 1; done; echo "provisioning DHCP timed out" >&2; exit 1'
"${ssh_lab[@]}" "set -e; sudo apt-get update -qq; sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $package; sudo apt-mark hold $package; dpkg-query -W $package"
