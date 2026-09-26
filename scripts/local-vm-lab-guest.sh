#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
  echo "usage: $0 NAME MEMORY_MIB SSH_PUBLIC_KEY_FILE" >&2
  exit 2
fi

name=$1
memory_mib=$2
public_key_file=$3
lab_dir=${NORTHSTAR_LAB_DIR:-/tmp/northstar-lab}
base_image=${NORTHSTAR_LAB_BASE_IMAGE:-/tmp/northstar-debian-13-generic-amd64.qcow2}
base_sha512=a733e7d49442a03e70d03e4eb5aaf3967f3efc69ef70952f9bb10fc1ee2c4876eb95956b5ad2d31350e5fada768feb651352535fb8cd1233f61998a5a7d2e93c

[[ $name =~ ^northstar-lab-[a-z0-9-]+$ ]] || { echo 'invalid lab VM name' >&2; exit 2; }
[[ $memory_mib =~ ^[0-9]+$ ]] && ((memory_mib >= 512 && memory_mib <= 8192)) || {
  echo 'memory must be between 512 and 8192 MiB' >&2
  exit 2
}
[[ -f $public_key_file ]] || { echo 'SSH public key file not found' >&2; exit 2; }
[[ -f $base_image ]] || { echo 'verified base image not found' >&2; exit 2; }
[[ $(sha512sum "$base_image" | cut -d' ' -f1) == "$base_sha512" ]] || {
  echo 'Debian base image SHA-512 mismatch' >&2
  exit 1
}
virsh net-info northstar-lab | rg -q '^Active:[[:space:]]+yes$' || {
  echo 'isolated lab network is not active' >&2
  exit 1
}
if virsh dominfo "$name" >/dev/null 2>&1; then
  echo "VM already exists: $name" >&2
  exit 1
fi

public_key=$(<"$public_key_file")
[[ $public_key =~ ^(ssh-ed25519|ssh-rsa)[[:space:]] ]] || {
  echo 'unsupported SSH public key' >&2
  exit 2
}

mkdir -p "$lab_dir/$name"
chmod 755 "$lab_dir" "$lab_dir/$name"
overlay=$lab_dir/$name/disk.qcow2
seed=$lab_dir/$name/seed.iso
[[ ! -e $overlay && ! -e $seed ]] || {
  echo "lab disk or seed already exists: $name" >&2
  exit 1
}

qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$overlay" 20G
chmod 644 "$overlay"
cat >"$lab_dir/$name/user-data" <<EOF
#cloud-config
hostname: $name
users:
  - name: lab
    groups: sudo
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $public_key
disable_root: true
ssh_pwauth: false
EOF
cat >"$lab_dir/$name/meta-data" <<EOF
instance-id: $name
local-hostname: $name
EOF
genisoimage -quiet -output "$seed" -volid cidata -joliet -rock \
  "$lab_dir/$name/user-data" "$lab_dir/$name/meta-data"
chmod 644 "$seed"

virt-install --connect qemu:///system --name "$name" \
  --memory "$memory_mib" --vcpus 2 --import --os-variant debian13 --boot uefi \
  --disk "path=$overlay,format=qcow2,bus=virtio" \
  --disk "path=$seed,device=cdrom" \
  --network network=northstar-lab,model=virtio \
  --graphics none --serial pty --console pty,target_type=serial \
  --noautoconsole
