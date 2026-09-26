#!/usr/bin/env bash
set -euo pipefail

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
dns_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-dns-ca" { split($5, parts, "/"); print parts[1] }')
[[ $dns_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")

setup_script=$(mktemp)
trap 'rm -f "$setup_script"' EXIT
cat >"$setup_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077
pki=/etc/northstar-lab-pki
install -d -m 700 "$pki"
if [[ ! -f $pki/ca.key ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -nodes -sha256 -days 30 -subj '/CN=Northstar Isolated Lab CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -addext 'subjectKeyIdentifier=hash' \
    -keyout "$pki/ca.key" -out "$pki/ca.pem"
fi
for name in ns-a ns-b prosody ejabberd infra; do
  if [[ ! -f $pki/$name.key ]]; then
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
      -nodes -sha256 -subj "/CN=$name.lab.test" \
      -keyout "$pki/$name.key" -out "$pki/$name.csr"
  fi
  if [[ ! -f $pki/$name.pem ]]; then
    cat >"$pki/$name.ext" <<EXT
[v3_req]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$name.lab.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
    openssl x509 -req -sha256 -days 14 \
      -in "$pki/$name.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" \
      -CAcreateserial -extfile "$pki/$name.ext" -extensions v3_req \
      -out "$pki/$name.pem"
  fi
  openssl verify -x509_strict -CAfile "$pki/ca.pem" "$pki/$name.pem"
done
EOF

scp "${ssh_opts[@]}" "$setup_script" "lab@$dns_ip:/tmp/northstar-lab-ca-setup.sh"
ssh "${ssh_opts[@]}" "lab@$dns_ip" 'sudo bash /tmp/northstar-lab-ca-setup.sh; rm -f /tmp/northstar-lab-ca-setup.sh'

for name in ns-a ns-b prosody ejabberd infra; do
  vm=northstar-lab-$name
  ip=$(virsh net-dhcp-leases northstar-lab | awk -v vm="$vm" '$6 == vm { split($5, parts, "/"); print parts[1] }')
  [[ $ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
  ssh "${ssh_opts[@]}" "lab@$ip" 'sudo install -d -m 700 /etc/northstar-lab-pki'
  ssh "${ssh_opts[@]}" "lab@$dns_ip" \
    "sudo tar -C /etc/northstar-lab-pki -cf - ca.pem $name.pem $name.key" |
    ssh "${ssh_opts[@]}" "lab@$ip" 'sudo tar -C /etc/northstar-lab-pki -xf -'
  case $name in
    prosody|ejabberd) owner="root:$name"; dir_mode=750 ;;
    infra) owner=root:postgres; dir_mode=750 ;;
    *) owner=lab:lab; dir_mode=700 ;;
  esac
  ssh "${ssh_opts[@]}" "lab@$ip" \
    "sudo chown $owner /etc/northstar-lab-pki /etc/northstar-lab-pki/$name.key; sudo chmod $dir_mode /etc/northstar-lab-pki; sudo chmod 640 /etc/northstar-lab-pki/$name.key; sudo chmod 644 /etc/northstar-lab-pki/ca.pem /etc/northstar-lab-pki/$name.pem; sudo install -m 644 /etc/northstar-lab-pki/ca.pem /usr/local/share/ca-certificates/northstar-lab-ca.crt; sudo update-ca-certificates >/dev/null; sudo openssl verify -x509_strict -CAfile /etc/northstar-lab-pki/ca.pem /etc/northstar-lab-pki/$name.pem"
done
