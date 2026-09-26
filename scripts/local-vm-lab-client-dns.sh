#!/usr/bin/env bash
set -euo pipefail

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
dns_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-dns-ca" { split($5, parts, "/"); print parts[1] }')
[[ $dns_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1

for guest in ns-a ns-b prosody ejabberd infra; do
  vm=northstar-lab-$guest
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || { echo "no lease: $vm" >&2; exit 1; }
  ssh "${ssh_opts[@]}" "lab@$ip" \
    "sudo tee /etc/systemd/network/09-northstar-lab.network >/dev/null; sudo resolvectl dns enp1s0 $dns_ip; sudo resolvectl domain enp1s0 lab.test; resolvectl query prosody.lab.test" <<EOF
[Match]
Name=enp1s0
[Network]
DHCP=ipv4
IPv6AcceptRA=yes
DNS=$dns_ip
Domains=lab.test
[DHCPv4]
UseDNS=no
UseDomains=no
EOF
  echo "$vm uses lab DNS"
done
