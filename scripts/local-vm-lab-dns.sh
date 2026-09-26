#!/usr/bin/env bash
set -euo pipefail

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

dns_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-dns-ca" { split($5, parts, "/"); print parts[1] }')
[[ $dns_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")

cat >"$work_dir/zone" <<'EOF'
$TTL 300
@ IN SOA dns-ca.lab.test. hostmaster.lab.test. ( 2026092602 3600 900 604800 300 )
@ IN NS dns-ca.lab.test.
postgres IN CNAME infra.lab.test.
redis IN CNAME infra.lab.test.
minio IN CNAME infra.lab.test.
EOF

for guest in ns-a ns-b prosody ejabberd infra dns-ca; do
  vm=northstar-lab-$guest
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || { echo "no IPv4 lease: $vm" >&2; exit 1; }
  ipv6=$(ssh "${ssh_opts[@]}" "lab@$ip" \
    "ip -6 -o addr show dev enp1s0 scope global | awk '\$3 == \"inet6\" { split(\$4, parts, \"/\"); print parts[1]; exit }'")
  [[ $ipv6 == fd7a:6e73:7461:72:* ]] || { echo "no lab IPv6 address: $vm" >&2; exit 1; }
  printf '%s IN A %s\n%s IN AAAA %s\n' "$guest" "$ip" "$guest" "$ipv6" >>"$work_dir/zone"
done

for guest in ns-a ns-b prosody ejabberd; do
  printf '_xmpp-server._tcp.%s IN SRV 0 5 5269 %s.lab.test.\n' "$guest" "$guest" >>"$work_dir/zone"
done
for guest in ns-a ns-b; do
  printf '_xmpps-server._tcp.%s IN SRV 0 5 5270 %s.lab.test.\n' "$guest" "$guest" >>"$work_dir/zone"
done

cat >"$work_dir/named.conf.local" <<'EOF'
zone "lab.test" {
  type primary;
  file "/var/lib/bind/lab.test.zone";
  dnssec-policy default;
  inline-signing yes;
  allow-query { 192.168.197.0/24; fd7a:6e73:7461:72::/64; localhost; };
  allow-transfer { none; };
};
EOF

scp "${ssh_opts[@]}" "$work_dir/zone" "$work_dir/named.conf.local" "lab@$dns_ip:/tmp/"
ssh "${ssh_opts[@]}" "lab@$dns_ip" \
  'sudo named-checkzone lab.test /tmp/zone; sudo install -o bind -g bind -m 640 /tmp/zone /var/lib/bind/lab.test.zone; sudo install -o root -g bind -m 640 /tmp/named.conf.local /etc/bind/named.conf.local; sudo named-checkconf -z; sudo systemctl restart named'
dig +time=2 +tries=1 +dnssec "@$dns_ip" ns-a.lab.test A
