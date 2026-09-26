#!/usr/bin/env bash
set -euo pipefail
set +x

# Run Redis with a lab-only TLS/mTLS listener and a namespaced command ACL.
key=${NORTHSTAR_LAB_SSH_KEY:-/tmp/northstar-lab-keys/id_ed25519}
[[ -f $key ]] || { echo 'lab SSH key not found' >&2; exit 2; }
infra_ip=$(virsh net-dhcp-leases northstar-lab | awk '$6 == "northstar-lab-infra" { split($5, parts, "/"); print parts[1] }')
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 1
ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=5 \
  -o StrictHostKeyChecking=accept-new \
  -o "UserKnownHostsFile=$(dirname "$key")/known_hosts" \
  "lab@$infra_ip" "sudo bash -s -- '$infra_ip'" <<'GUEST'
set -euo pipefail
set +x
umask 077
infra_ip=$1
[[ $infra_ip =~ ^192\.168\.197\.[0-9]+$ ]] || exit 2
install -d -o root -g redis -m 750 /etc/northstar-lab-redis
install -d -o redis -g redis -m 700 /var/lib/northstar-lab-redis
password_file=/etc/northstar-lab-redis/password
if [[ ! -e $password_file ]]; then
  openssl rand -hex 24 >"$password_file"
fi
chown root:redis "$password_file"
chmod 640 "$password_file"
password=$(cat "$password_file")
[[ $password =~ ^[a-f0-9]{48}$ ]] || exit 1
install -o root -g redis -m 640 \
  /etc/northstar-lab-pki/infra.pem /etc/northstar-lab-redis/server.pem
install -o root -g redis -m 640 \
  /etc/northstar-lab-pki/infra.key /etc/northstar-lab-redis/server.key
install -o root -g redis -m 640 \
  /etc/northstar-lab-pki/ca.pem /etc/northstar-lab-redis/ca.pem
cat >/etc/northstar-lab-redis/users.acl <<ACL
user default off
user northstar on >$password ~northstar:ns-a.lab.test:* &northstar:ns-a.lab.test:* +ping +time +get +set +setex +expire +ttl +exists +del +sadd +srem +smembers +scard +zadd +zrem +zrangebyscore +zremrangebyscore +scan +publish +subscribe +unsubscribe +psubscribe +punsubscribe +eval +evalsha +script|load +hget +hset +hdel +hexists +hlen +hvals +hgetall +hkeys +hincrby
ACL
chown root:redis /etc/northstar-lab-redis/users.acl
chmod 640 /etc/northstar-lab-redis/users.acl
cat >/etc/northstar-lab-redis/redis.conf <<CONF
bind $infra_ip
port 0
tls-port 6379
tls-cert-file /etc/northstar-lab-redis/server.pem
tls-key-file /etc/northstar-lab-redis/server.key
tls-ca-cert-file /etc/northstar-lab-redis/ca.pem
tls-auth-clients yes
protected-mode yes
aclfile /etc/northstar-lab-redis/users.acl
dir /var/lib/northstar-lab-redis
appendonly yes
save ""
daemonize no
logfile ""
CONF
chown root:redis /etc/northstar-lab-redis/redis.conf
chmod 640 /etc/northstar-lab-redis/redis.conf
cat >/etc/systemd/system/northstar-lab-redis.service <<'UNIT'
[Unit]
Description=Redis TLS control plane for the isolated Northstar lab
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=redis
Group=redis
ExecStart=/usr/bin/redis-server /etc/northstar-lab-redis/redis.conf
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
systemctl disable --now redis-server.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable northstar-lab-redis.service >/dev/null
systemctl restart northstar-lab-redis.service
ready=false
for _ in $(seq 1 20); do
  if [[ $(REDISCLI_AUTH="$password" redis-cli --tls \
    --cacert /etc/northstar-lab-redis/ca.pem \
    --cert /etc/northstar-lab-pki/infra.pem \
    --key /etc/northstar-lab-pki/infra.key \
    --sni infra.lab.test --user northstar -h "$infra_ip" -p 6379 \
    ping 2>/dev/null) == PONG ]]; then
    ready=true
    break
  fi
  sleep 1
done
[[ $ready == true ]] || { echo 'Redis mTLS endpoint did not become ready' >&2; exit 1; }
allowed=$(REDISCLI_AUTH="$password" redis-cli --tls \
  --cacert /etc/northstar-lab-redis/ca.pem \
  --cert /etc/northstar-lab-pki/infra.pem --key /etc/northstar-lab-pki/infra.key \
  --sni infra.lab.test --user northstar -h "$infra_ip" -p 6379 \
  scard northstar:ns-a.lab.test:lab-probe)
[[ $allowed == 0 ]] || { echo 'Redis ACL denied the deployment namespace' >&2; exit 1; }
denied=$(REDISCLI_AUTH="$password" redis-cli --tls \
  --cacert /etc/northstar-lab-redis/ca.pem \
  --cert /etc/northstar-lab-pki/infra.pem --key /etc/northstar-lab-pki/infra.key \
  --sni infra.lab.test --user northstar -h "$infra_ip" -p 6379 \
  scard outside:cluster 2>&1 || true)
if [[ $denied != *NOPERM* ]]; then
  echo 'Redis ACL did not reject an out-of-namespace key' >&2
  exit 1
fi
echo 'Redis mTLS and namespaced ACL checks passed'
GUEST
