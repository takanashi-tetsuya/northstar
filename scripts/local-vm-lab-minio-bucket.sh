#!/usr/bin/env bash
set -euo pipefail
set +x

key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
infra_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-infra" { split($5, parts, "/"); print parts[1] }')
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=accept-new \
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts" \
  "lab@$infra_ip" 'sudo bash -s' <<'GUEST'
set -euo pipefail
set +x
umask 077
config=$(mktemp)
trap 'rm -f "$config"' EXIT
access=$(cat /etc/northstar-lab-minio/access-key)
secret=$(cat /etc/northstar-lab-minio/secret-key)
cat >"$config" <<CONF
aws-sigv4 = "aws:amz:us-east-1:s3"
user = "$access:$secret"
cacert = "/etc/northstar-lab-pki/ca.pem"
silent
show-error
CONF
endpoint=https://infra.lab.test:9000/northstar-lab-uploads
status=$(curl --config "$config" --head --output /dev/null \
  --write-out '%{http_code}' "$endpoint")
case $status in
  200) ;;
  404) curl --config "$config" --fail-with-body --request PUT \
    --output /dev/null "$endpoint" ;;
  *) echo "unexpected MinIO bucket status: $status" >&2; exit 1 ;;
esac
curl --config "$config" --fail-with-body --request PUT \
  --header 'Content-Type: application/xml' --data-binary @- \
  --output /dev/null "$endpoint?versioning" <<'XML'
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>
XML
versioning=$(curl --config "$config" --fail-with-body "$endpoint?versioning")
[[ $versioning == *'<Status>Enabled</Status>'* ]] || {
  echo 'MinIO bucket did not enable versioning' >&2
  exit 1
}
echo 'northstar-lab-uploads bucket has versioning enabled'
GUEST
