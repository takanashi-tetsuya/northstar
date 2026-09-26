#!/usr/bin/env bash
set -euo pipefail

# Stop one independent peer, prove a durable S2S queue entry, then receive it
# after the peer returns. The trap restores the peer even when an assertion fails.
[[ $# -eq 1 && ( $1 == prosody || $1 == ejabberd ) ]] || {
  echo "usage: $0 prosody|ejabberd" >&2
  exit 2
}
peer_name=$1
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
lease_ip() {
  local vm=northstar-lab-$1 ip
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || return 1
  printf '%s' "$ip"
}
peer=lab@$(lease_ip "$peer_name")
node=lab@$(lease_ip ns-a)
infra=lab@$(lease_ip infra)
restore_peer() {
  ssh "${ssh_opts[@]}" "$peer" "sudo systemctl start $peer_name" >/dev/null 2>&1 || true
}
trap restore_peer EXIT

ssh "${ssh_opts[@]}" "$peer" \
  "sudo systemctl stop $peer_name; ! systemctl is-active --quiet $peer_name"
marker=$(ssh "${ssh_opts[@]}" "$node" \
  "python3 /home/lab/northstar/local-vm-lab-federation.py $peer_name --mode send")
[[ $marker =~ ^lab-retry-[0-9]+$ ]] || {
  echo 'the sender did not return its unique message marker' >&2
  exit 1
}
sleep 2
queued=$(ssh "${ssh_opts[@]}" "$infra" \
  "sudo -u postgres psql -d xmpp --no-psqlrc -Atqc \"SELECT COUNT(*) FROM s2s_outbox WHERE target_domain = '$peer_name.lab.test'\"")
[[ $queued =~ ^[0-9]+$ && $queued -gt 0 ]] || {
  echo 'Northstar did not retain a queued S2S item while the peer was down' >&2
  exit 1
}
printf '%s down: %s queued Northstar S2S item(s)\n' "$peer_name" "$queued"
ssh "${ssh_opts[@]}" "$peer" \
  "sudo systemctl start $peer_name; systemctl is-active --quiet $peer_name"
ssh "${ssh_opts[@]}" "$node" \
  "python3 /home/lab/northstar/local-vm-lab-federation.py $peer_name --mode receive --marker $marker"
