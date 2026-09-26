#!/usr/bin/env bash
set -euo pipefail

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
prosody_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-prosody" { split($5, parts, "/"); print parts[1] }')
ejabberd_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-ejabberd" { split($5, parts, "/"); print parts[1] }')
dns_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-dns-ca" { split($5, parts, "/"); print parts[1] }')
[[ $prosody_ip =~ ^192\.168\.197\.[0-9]+$ && $ejabberd_ip =~ ^192\.168\.197\.[0-9]+$ && $dns_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1

ssh "${ssh_opts[@]}" "lab@$prosody_ip" "sudo bash -s -- $dns_ip" <<'EOF'
set -euo pipefail
dns_ip=$1
sed -i '/^unbound = { resolvconf = false;/d' /etc/prosody/prosody.cfg.lua
sed -i "1i unbound = { resolvconf = false; forward = \"$dns_ip\"; options = { [\"local-zone\"] = \"lab.test. transparent\" } }" /etc/prosody/prosody.cfg.lua
sed -i 's#debug = "/var/log/prosody/prosody.log"#info = "/var/log/prosody/prosody.log"#' /etc/prosody/prosody.cfg.lua
cat >/etc/prosody/conf.d/northstar-lab.cfg.lua <<'CONFIG'
VirtualHost "prosody.lab.test"
  ssl = {
    certificate = "/etc/northstar-lab-pki/prosody.pem";
    key = "/etc/northstar-lab-pki/prosody.key";
  }
CONFIG
sed -i 's/^VirtualHost "localhost"$/--VirtualHost "localhost"/' /etc/prosody/prosody.cfg.lua /etc/prosody/conf.d/localhost.cfg.lua
prosodyctl check config
systemctl restart prosody
systemctl is-active prosody
EOF

ssh "${ssh_opts[@]}" "lab@$ejabberd_ip" \
  'set -e; sudo sh -c "cat /etc/northstar-lab-pki/ejabberd.pem /etc/northstar-lab-pki/ejabberd.key > /etc/northstar-lab-pki/ejabberd-combined.pem"; sudo chown root:ejabberd /etc/northstar-lab-pki/ejabberd-combined.pem; sudo chmod 640 /etc/northstar-lab-pki/ejabberd-combined.pem; sudo sed -i -e "s/^  - localhost$/  - ejabberd.lab.test/" -e "s#\"/etc/ejabberd/ejabberd.pem\"#\"/etc/northstar-lab-pki/ejabberd-combined.pem\"#" /etc/ejabberd/ejabberd.yml; sudo systemctl restart ejabberd; systemctl is-active ejabberd; sudo ejabberdctl status'
