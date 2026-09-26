#!/usr/bin/env bash
set -euo pipefail
set +x

# Install the repository-pinned MinIO build on the infra guest's own data disk.
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
package=${NORTHSTAR_LAB_MINIO_DEB:-/tmp/northstar-lab-minio-20250907.deb}
checksum=eeda08f699f6592d1b868ac8bda864ae2cacdb5ee1b888663366e8c8ff566249
[[ -f $key && -f $package ]] || { echo 'lab key or pinned MinIO package not found' >&2; exit 2; }
printf '%s  %s\n' "$checksum" "$package" | sha256sum --check --status || {
  echo 'pinned MinIO package checksum mismatch' >&2
  exit 1
}
infra_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-infra" { split($5, parts, "/"); print parts[1] }')
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
ssh_opts=(-i "$key" -o BatchMode=yes -o ConnectTimeout=5
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts")
remote=lab@$infra_ip
disk=/tmp/northstar-lab/northstar-lab-infra/minio-data.qcow2
if [[ ! -e $disk ]]; then
  qemu-img create -f qcow2 "$disk" 10G >/dev/null
fi
[[ -f $disk && ! -L $disk ]] || exit 1
if ! virsh domblklist northstar-lab-infra | grep -Fq "$disk"; then
  virsh attach-disk northstar-lab-infra "$disk" vdb \
    --targetbus virtio --subdriver qcow2 --live --config >/dev/null
fi
scp "${ssh_opts[@]}" "$package" "$remote:/tmp/northstar-lab-minio.deb"
ssh "${ssh_opts[@]}" "$remote" "sudo bash -s -- '$infra_ip'" <<'GUEST'
set -euo pipefail
set +x
umask 077
infra_ip=$1
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 2
for _ in $(seq 1 20); do
  [[ -b /dev/vdb ]] && break
  sleep 1
done
[[ -b /dev/vdb ]] || { echo 'dedicated MinIO disk did not attach' >&2; exit 1; }
filesystem=$(blkid -s TYPE -o value /dev/vdb 2>/dev/null || true)
if [[ -z $filesystem ]]; then
  mkfs.ext4 -q /dev/vdb
elif [[ $filesystem != ext4 ]]; then
  echo 'MinIO disk has an unexpected filesystem' >&2
  exit 1
fi
uuid=$(blkid -s UUID -o value /dev/vdb)
[[ $uuid =~ ^[a-f0-9-]+$ ]] || exit 1
install -d -m 700 /var/lib/northstar-lab-minio
if ! grep -Fq "UUID=$uuid " /etc/fstab; then
  printf 'UUID=%s /var/lib/northstar-lab-minio ext4 defaults,nofail 0 2\n' "$uuid" >>/etc/fstab
fi
mountpoint -q /var/lib/northstar-lab-minio || mount /var/lib/northstar-lab-minio
if ! id northstar-minio >/dev/null 2>&1; then
  useradd --system --home /var/lib/northstar-lab-minio --shell /usr/sbin/nologin northstar-minio
fi
chown northstar-minio:northstar-minio /var/lib/northstar-lab-minio
chmod 700 /var/lib/northstar-lab-minio

install -d -m 755 /opt/northstar-lab-minio
extract=$(mktemp -d)
trap 'rm -rf "$extract" /tmp/northstar-lab-minio.deb' EXIT
dpkg-deb --extract /tmp/northstar-lab-minio.deb "$extract"
install -m 755 "$extract/usr/local/bin/minio" /opt/northstar-lab-minio/minio
install -d -o northstar-minio -g northstar-minio -m 700 /etc/northstar-lab-minio
install -d -o northstar-minio -g northstar-minio -m 700 /etc/northstar-lab-minio/certs
install -m 644 /etc/northstar-lab-pki/infra.pem /etc/northstar-lab-minio/certs/public.crt
install -o northstar-minio -g northstar-minio -m 600 \
  /etc/northstar-lab-pki/infra.key /etc/northstar-lab-minio/certs/private.key
chown northstar-minio:northstar-minio /etc/northstar-lab-minio/certs/public.crt
for name in access-key secret-key; do
  path=/etc/northstar-lab-minio/$name
  if [[ ! -e $path ]]; then
    openssl rand -hex 24 >"$path"
  fi
  chown northstar-minio:northstar-minio "$path"
  chmod 600 "$path"
done
cat >/etc/systemd/system/northstar-lab-minio.service <<UNIT
[Unit]
Description=Versioned MinIO for the isolated Northstar lab
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/var/lib/northstar-lab-minio
[Service]
Type=simple
User=northstar-minio
Group=northstar-minio
Environment=MINIO_ROOT_USER_FILE=/etc/northstar-lab-minio/access-key
Environment=MINIO_ROOT_PASSWORD_FILE=/etc/northstar-lab-minio/secret-key
Environment=MINIO_BROWSER=off
ExecStart=/opt/northstar-lab-minio/minio server /var/lib/northstar-lab-minio --address ${infra_ip}:9000 --console-address 127.0.0.1:9001 --certs-dir /etc/northstar-lab-minio/certs
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable northstar-lab-minio.service >/dev/null
systemctl restart northstar-lab-minio.service
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error --cacert /etc/northstar-lab-pki/ca.pem \
    --resolve "infra.lab.test:9000:$infra_ip" \
    https://infra.lab.test:9000/minio/health/live >/dev/null 2>&1; then
    echo 'versioned MinIO TLS endpoint ready'
    exit 0
  fi
  sleep 1
done
systemctl status northstar-lab-minio.service --no-pager -n 20 >&2
exit 1
GUEST
