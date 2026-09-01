#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
verifier="$project_dir/scripts/verify-production-certificate.sh"
work_dir="$(mktemp -d /tmp/northstar-certificate-security.XXXXXX)"
cleanup() {
  case "$work_dir" in
    /tmp/northstar-certificate-security.*) rm -rf -- "$work_dir" ;;
  esac
}
trap cleanup EXIT
umask 077

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 397 \
  -subj '/CN=Northstar regression root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$work_dir/root.key" -out "$work_dir/root.crt" >/dev/null 2>&1

make_leaf() {
  name=$1
  bits=$2
  domain=$3
  constraints=$4
  usage=$5
  openssl req -new -newkey "rsa:$bits" -nodes -sha256 \
    -subj "/CN=$domain" \
    -keyout "$work_dir/$name.key" -out "$work_dir/$name.csr" >/dev/null 2>&1
  {
    echo "basicConstraints=critical,$constraints"
    echo "keyUsage=critical,$usage"
    echo 'extendedKeyUsage=serverAuth'
    echo "subjectAltName=DNS:$domain"
  } > "$work_dir/$name.ext"
  openssl x509 -req -in "$work_dir/$name.csr" \
    -CA "$work_dir/root.crt" -CAkey "$work_dir/root.key" -CAcreateserial \
    -days 397 -sha256 -extfile "$work_dir/$name.ext" \
    -out "$work_dir/$name.crt" >/dev/null 2>&1
  chmod 600 "$work_dir/$name.key"
  chmod 644 "$work_dir/$name.crt"
}

make_leaf valid 3072 xmpp.example.test CA:FALSE digitalSignature
make_leaf other 3072 other.example.test CA:FALSE digitalSignature
make_leaf weak 2048 xmpp.example.test CA:FALSE digitalSignature
make_leaf ca_leaf 3072 xmpp.example.test CA:TRUE digitalSignature,keyCertSign

openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=xmpp.example.test' \
  -keyout "$work_dir/cn_only.key" -out "$work_dir/cn_only.csr" >/dev/null 2>&1
cat > "$work_dir/cn_only.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$work_dir/cn_only.csr" \
  -CA "$work_dir/root.crt" -CAkey "$work_dir/root.key" -CAcreateserial \
  -days 397 -sha256 -extfile "$work_dir/cn_only.ext" \
  -out "$work_dir/cn_only.crt" >/dev/null 2>&1
chmod 600 "$work_dir/cn_only.key"
chmod 644 "$work_dir/cn_only.crt"

private_fragment=$(awk 'NR == 2 { print substr($0, 1, 24) }' "$work_dir/valid.key")
valid_output=$(sh "$verifier" \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/root.crt" 2>&1)
grep -F 'validation passed' <<<"$valid_output" >/dev/null
[[ "$valid_output" != *'PRIVATE KEY'* ]]
[[ -z "$private_fragment" || "$valid_output" != *"$private_fragment"* ]]
trace_output=$(sh -x "$verifier" \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/root.crt" 2>&1)
[[ "$trace_output" != *'PRIVATE KEY'* ]]
[[ -z "$private_fragment" || "$trace_output" != *"$private_fragment"* ]]

expect_failure() {
  name=$1
  shift
  set +e
  output=$(sh "$verifier" "$@" 2>&1)
  status=$?
  set -e
  if [[ $status -eq 0 ]]; then
    echo "certificate regression unexpectedly passed: $name" >&2
    exit 1
  fi
  [[ "$output" != *'PRIVATE KEY'* ]]
  [[ -z "$private_fragment" || "$output" != *"$private_fragment"* ]]
}

expect_failure wrong-domain \
  "$work_dir/valid.crt" "$work_dir/valid.key" wrong.example.test "$work_dir/root.crt"
expect_failure mismatched-key \
  "$work_dir/valid.crt" "$work_dir/other.key" xmpp.example.test "$work_dir/root.crt"
expect_failure weak-key \
  "$work_dir/weak.crt" "$work_dir/weak.key" xmpp.example.test "$work_dir/root.crt"
expect_failure ca-leaf \
  "$work_dir/ca_leaf.crt" "$work_dir/ca_leaf.key" xmpp.example.test "$work_dir/root.crt"
expect_failure cn-only-identity \
  "$work_dir/cn_only.crt" "$work_dir/cn_only.key" xmpp.example.test "$work_dir/root.crt"

cp "$work_dir/valid.crt" "$work_dir/mixed.crt"
cat "$work_dir/valid.key" >> "$work_dir/mixed.crt"
expect_failure private-key-in-certificate \
  "$work_dir/mixed.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/root.crt"

chmod 644 "$work_dir/valid.key"
expect_failure permissive-key-mode \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/root.crt"
chmod 600 "$work_dir/valid.key"

ln -s "$work_dir/valid.key" "$work_dir/key-link"
expect_failure key-symlink \
  "$work_dir/valid.crt" "$work_dir/key-link" xmpp.example.test "$work_dir/root.crt"

cp "$work_dir/root.crt" "$work_dir/writable-root.crt"
chmod 666 "$work_dir/writable-root.crt"
expect_failure writable-ca \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/writable-root.crt"

cp "$work_dir/root.crt" "$work_dir/mixed-root.crt"
cat "$work_dir/root.key" >> "$work_dir/mixed-root.crt"
expect_failure private-key-in-ca \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/mixed-root.crt"

ln -s "$work_dir/root.crt" "$work_dir/root-link.crt"
expect_failure ca-symlink \
  "$work_dir/valid.crt" "$work_dir/valid.key" xmpp.example.test "$work_dir/root-link.crt"

development_output=$(bash "$project_dir/scripts/generate-development-certificate.sh" \
  "$work_dir/development.crt" "$work_dir/development.key" 2>&1)
[[ "$development_output" == *'DEVELOPMENT-ONLY'* ]]
development_fragment=$(awk 'NR == 2 { print substr($0, 1, 24) }' "$work_dir/development.key")
[[ -z "$development_fragment" || "$development_output" != *"$development_fragment"* ]]
expect_failure development-is-not-production \
  "$work_dir/development.crt" "$work_dir/development.key" localhost "$work_dir/development.crt"

ln -s "$work_dir/development-link-target" "$work_dir/development-link.key"
if bash "$project_dir/scripts/generate-development-certificate.sh" \
  "$work_dir/development-link.crt" "$work_dir/development-link.key" >/dev/null 2>&1; then
  echo "development certificate generator followed a dangling key symlink" >&2
  exit 1
fi
[[ ! -e "$work_dir/development-link-target" ]]

echo "certificate security regression tests passed"
