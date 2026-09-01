#!/usr/bin/env bash
set -euo pipefail
set +x

# Read-only public federation preflight. This script performs DNS, HTTPS and
# TLS reads only. It never changes DNS, certificates, remote servers or the
# local Northstar database. Run it from a network outside the deployment for
# meaningful reachability evidence.

domain_input="${1:-${XMPP_DOMAIN:-}}"
dane_mode="${FEDERATION_DANE_MODE:-off}"
external_enabled="${S2S_SASL_EXTERNAL_ENABLED:-true}"
require_xep_0487="${NORTHSTAR_PREFLIGHT_REQUIRE_XEP0487:-false}"
max_endpoints="${NORTHSTAR_PREFLIGHT_MAX_ENDPOINTS:-64}"

failures=0
warnings=0
passes=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
warn() { echo "WARN: $*" >&2; warnings=$((warnings + 1)); }
pass() { echo "PASS: $*"; passes=$((passes + 1)); }

case "$dane_mode" in off|opportunistic|required) ;; *) echo "invalid FEDERATION_DANE_MODE" >&2; exit 2 ;; esac
case "$external_enabled" in true|false) ;; *) echo "invalid S2S_SASL_EXTERNAL_ENABLED" >&2; exit 2 ;; esac
case "$require_xep_0487" in true|false) ;; *) echo "invalid NORTHSTAR_PREFLIGHT_REQUIRE_XEP0487" >&2; exit 2 ;; esac
[[ "$max_endpoints" =~ ^[1-9][0-9]*$ ]] && (( max_endpoints <= 256 )) || {
  echo "NORTHSTAR_PREFLIGHT_MAX_ENDPOINTS must be 1..256" >&2
  exit 2
}

for command_name in delv openssl curl python3 awk sed grep mktemp timeout xxd; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "required preflight command is unavailable: $command_name" >&2
    exit 2
  }
done

[[ -n "$domain_input" ]] || { echo "usage: $0 PUBLIC_XMPP_DOMAIN" >&2; exit 2; }
domain="$(python3 -c 'import sys; value=sys.argv[1].rstrip("."); encoded=value.encode("idna").decode("ascii").lower(); print(encoded)' "$domain_input" 2>/dev/null)" || {
  echo "XMPP domain is not a valid IDNA DNS name" >&2
  exit 2
}
python3 - "$domain" <<'PY' || exit 2
import ipaddress, re, sys
value = sys.argv[1]
if len(value) > 253 or not value or value == "localhost":
    raise SystemExit("XMPP domain must be a public DNS name")
try:
    ipaddress.ip_address(value)
except ValueError:
    pass
else:
    raise SystemExit("XMPP domain cannot be an IP literal")
for label in value.split("."):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
        raise SystemExit("XMPP domain contains an invalid DNS label")
PY

runtime_dir="$(mktemp -d /tmp/northstar-external-preflight.XXXXXX)"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  case "$runtime_dir" in
    /tmp/northstar-external-preflight.*) rm -rf -- "$runtime_dir" ;;
    *) echo "refusing to remove unexpected preflight directory: $runtime_dir" >&2; exit 1 ;;
  esac
  if [[ -e "$runtime_dir" ]]; then
    echo "preflight temporary directory remained: $runtime_dir" >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

DNS_STATUS=""
DNS_RECORDS=""
dns_query() {
  local owner="$1"
  local record_type="$2"
  local transcript short_output
  transcript="$(delv "$owner" "$record_type" 2>&1 || true)"
  short_output="$(delv +short "$owner" "$record_type" 2>/dev/null || true)"
  if grep -qi 'fully validated' <<<"$transcript"; then
    DNS_STATUS=secure
  elif grep -Eqi 'broken trust chain|validation failure|bogus|SERVFAIL' <<<"$transcript"; then
    DNS_STATUS=bogus
  elif grep -qi 'unsigned answer' <<<"$transcript"; then
    DNS_STATUS=insecure
  elif [[ -z "$short_output" ]] && grep -Eqi 'ncache|NXDOMAIN|not found|no records' <<<"$transcript"; then
    DNS_STATUS=absent
  else
    DNS_STATUS=indeterminate
  fi
  DNS_RECORDS="$(sed -e 's/[[:space:]]\+/ /g' -e 's/[[:space:]]*$//' <<<"$short_output")"
}

is_global_ip() {
  python3 - "$1" <<'PY'
import ipaddress, sys
address = ipaddress.ip_address(sys.argv[1])
raise SystemExit(0 if address.is_global else 1)
PY
}

connect_literal() {
  local ip="$1" port="$2"
  if [[ "$ip" == *:* ]]; then printf '[%s]:%s' "$ip" "$port"; else printf '%s:%s' "$ip" "$port"; fi
}

extract_leaf() {
  local transcript="$1" output="$2"
  awk '/-----BEGIN CERTIFICATE-----/{capture=1} capture{print} /-----END CERTIFICATE-----/{exit}' "$transcript" >"$output"
  [[ -s "$output" ]] && openssl x509 -in "$output" -noout >/dev/null 2>&1
}

extract_chain() {
  local transcript="$1" output="$2"
  awk '/-----BEGIN CERTIFICATE-----/{capture=1} capture{print} /-----END CERTIFICATE-----/{capture=0}' "$transcript" >"$output"
  [[ -s "$output" ]]
}

xmpp_certificate_identity() {
  local certificate="$1" reference="$2" escaped san
  if openssl x509 -in "$certificate" -noout -checkhost "$reference" >/dev/null 2>&1; then
    return 0
  fi
  escaped="${reference//./[.]}"
  san="$(openssl x509 -in "$certificate" -noout -ext subjectAltName 2>/dev/null || true)"
  grep -Eiq "(SRVName|1[.]3[.]6[.]1[.]5[.]5[.]7[.]8[.]7)[^,]*_xmpp-server[.]${escaped}([,[:space:]]|$)" <<<"$san" \
    || grep -Eiq "(XmppAddr|1[.]3[.]6[.]1[.]5[.]5[.]7[.]8[.]5)[^,]*${escaped}([,[:space:]]|$)" <<<"$san"
}

strong_leaf_key() {
  local certificate="$1" algorithm bits signature
  signature="$(openssl x509 -in "$certificate" -noout -text | sed -n 's/^[[:space:]]*Signature Algorithm: //p' | head -n1)"
  case "$signature" in *md2*|*MD2*|*md5*|*MD5*|*sha1*|*SHA1*) return 1 ;; esac
  algorithm="$(openssl x509 -in "$certificate" -noout -text | sed -n 's/^[[:space:]]*Public Key Algorithm: //p' | head -n1)"
  bits="$(openssl x509 -in "$certificate" -pubkey -noout \
    | openssl pkey -pubin -text -noout 2>/dev/null \
    | sed -n 's/^Public-Key: (\([0-9][0-9]*\) bit)$/\1/p' | head -n1)"
  case "$algorithm" in
    rsaEncryption) [[ -n "$bits" ]] && (( bits >= 2048 )) ;;
    id-ecPublicKey) [[ -n "$bits" ]] && (( bits >= 256 )) ;;
    ED25519|Ed25519) return 0 ;;
    *) return 1 ;;
  esac
}

selector_hex() {
  local certificate="$1" selector="$2" matching="$3" raw
  if [[ "$selector" == 0 ]]; then
    raw="$(openssl x509 -in "$certificate" -outform DER | xxd -p -c 1000000 | tr -d '\r\n')"
  else
    raw="$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER | xxd -p -c 1000000 | tr -d '\r\n')"
  fi
  case "$matching" in
    0) printf '%s' "$raw" ;;
    1) printf '%s' "$raw" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c 1000000 | tr -d '\r\n' ;;
    2) printf '%s' "$raw" | xxd -r -p | openssl dgst -sha512 -binary | xxd -p -c 1000000 | tr -d '\r\n' ;;
  esac
}

TLSA_STATUS="absent"
TLSA_MATCH="none"
TLSA_USABLE=0
check_tlsa() {
  local owner="$1" certificate="$2"
  local usage selector matching association actual supported=0 matched=""
  dns_query "$owner" TLSA
  TLSA_STATUS="$DNS_STATUS"
  TLSA_MATCH=none
  TLSA_USABLE=0
  if [[ "$DNS_STATUS" == bogus || "$DNS_STATUS" == indeterminate ]]; then
    fail "$owner TLSA validation is $DNS_STATUS"
    return
  fi
  [[ -n "$DNS_RECORDS" ]] || return
  if [[ "$DNS_STATUS" != secure ]]; then
    fail "$owner publishes TLSA without a locally validated DNSSEC proof"
    return
  fi
  while read -r usage selector matching association extra; do
    [[ -n "${usage:-}" ]] || continue
    if [[ -n "${extra:-}" || ! "$usage" =~ ^[0-3]$ || ! "$selector" =~ ^[01]$ || ! "$matching" =~ ^[0-2]$ || ! "$association" =~ ^[0-9A-Fa-f]+$ ]]; then
      fail "$owner contains a malformed TLSA record"
      continue
    fi
    if [[ "$usage" != 1 && "$usage" != 3 ]]; then
      continue
    fi
    supported=$((supported + 1))
    TLSA_USABLE=$((TLSA_USABLE + 1))
    actual="$(selector_hex "$certificate" "$selector" "$matching")"
    if [[ "${actual,,}" == "${association,,}" ]]; then
      matched="$usage"
      TLSA_MATCH="$usage"
    fi
  done <<<"$DNS_RECORDS"
  if (( supported == 0 )); then
    fail "$owner secure TLSA RRset contains no RFC 7712 usage 1 or 3 record"
  elif [[ -z "$matched" ]]; then
    fail "$owner secure TLSA RRset does not match the live end-entity certificate"
  else
    pass "$owner secure TLSA usage $matched matched the live certificate"
  fi
}

probe_tls_address() {
  local method="$1" target="$2" port="$3" ip="$4" service_domain="$5" srv_status="$6" address_status="$7"
  local label="$method $target:$port via $ip" connect transcript leaf chain tls_flag version_args=() starttls_args=()
  connect="$(connect_literal "$ip" "$port")"
  [[ "$method" == direct ]] && starttls_args=(-alpn xmpp-server) || starttls_args=(-starttls xmpp-server -xmpphost "$service_domain")
  for tls_flag in tls1_2 tls1_3; do
    [[ "$tls_flag" == tls1_2 ]] && version_args=(-tls1_2) || version_args=(-tls1_3)
    transcript="$runtime_dir/${method}-${port}-${ip//:/_}-${tls_flag}.txt"
    if ! timeout 25 openssl s_client -connect "$connect" -servername "$service_domain" \
      "${starttls_args[@]}" "${version_args[@]}" -showcerts </dev/null >"$transcript" 2>&1; then
      fail "$label did not complete a $tls_flag handshake"
      continue
    fi
    if grep -Eqi 'Cipher is \(NONE\)|handshake failure|no peer certificate' "$transcript"; then
      fail "$label returned no authenticated $tls_flag TLS session"
      continue
    fi
    if [[ "$method" == direct ]] && ! grep -Fq 'ALPN protocol: xmpp-server' "$transcript"; then
      fail "$label did not select Direct TLS ALPN xmpp-server"
    else
      if [[ "$method" == direct ]]; then
        pass "$label negotiated $tls_flag with xmpp-server ALPN"
      else
        pass "$label negotiated $tls_flag with mandatory STARTTLS"
      fi
    fi
  done

  transcript="$runtime_dir/${method}-${port}-${ip//:/_}-certificate.txt"
  timeout 25 openssl s_client -connect "$connect" -servername "$service_domain" \
    "${starttls_args[@]}" -showcerts </dev/null >"$transcript" 2>&1 || true
  leaf="$runtime_dir/${method}-${port}-${ip//:/_}-leaf.pem"
  if ! extract_leaf "$transcript" "$leaf"; then
    fail "$label did not present a parseable X.509 leaf"
    return
  fi
  chain="$runtime_dir/${method}-${port}-${ip//:/_}-chain.pem"
  extract_chain "$transcript" "$chain" || fail "$label certificate chain could not be extracted"
  strong_leaf_key "$leaf" || fail "$label uses a weak or unsupported certificate key/signature"

  local pkix_ok=false
  if timeout 25 openssl s_client -connect "$connect" -servername "$service_domain" \
    "${starttls_args[@]}" -verify_return_error </dev/null \
    >"$runtime_dir/${method}-${port}-${ip//:/_}-pkix.txt" 2>&1; then
    if xmpp_certificate_identity "$leaf" "$service_domain"; then
      pkix_ok=true
      pass "$label passed public PKIX chain, time and XMPP reference-identity validation"
    fi
  fi
  if [[ "$external_enabled" == true ]]; then
    if openssl verify -purpose sslclient -untrusted "$chain" "$leaf" >/dev/null 2>&1; then
      pass "$label chain is valid for TLS client authentication used by SASL EXTERNAL"
    else
      fail "$label chain is not valid for TLS client authentication while SASL EXTERNAL is enabled"
    fi
  fi

  if [[ "$dane_mode" == off ]]; then
    TLSA_STATUS=disabled
    TLSA_MATCH=none
    TLSA_USABLE=0
  elif [[ "$srv_status" == secure && "$address_status" == secure ]]; then
    check_tlsa "_${port}._tcp.${target%.}." "$leaf"
  else
    TLSA_STATUS=unavailable
    TLSA_MATCH=none
    TLSA_USABLE=0
    if [[ "$dane_mode" == required ]]; then
      fail "$label lacks a DNSSEC-secure SRV-to-address binding required by DANE"
    elif [[ "$dane_mode" == opportunistic ]]; then
      warn "$label SRV-to-address binding is not DNSSEC secure; using PKIX only"
    fi
  fi
  case "$dane_mode" in
    off)
      [[ "$pkix_ok" == true ]] || fail "$label requires PKIX because DANE mode is off"
      ;;
    opportunistic)
      if [[ "$TLSA_STATUS" == secure ]]; then
        [[ "$TLSA_MATCH" != none ]] || fail "$label cannot downgrade from a secure TLSA policy"
        [[ "$TLSA_MATCH" != 1 || "$pkix_ok" == true ]] || fail "$label usage 1 requires PKIX"
      else
        [[ "$pkix_ok" == true ]] || fail "$label has neither secure DANE nor valid PKIX"
      fi
      ;;
    required)
      [[ "$TLSA_STATUS" == secure && "$TLSA_MATCH" != none ]] || fail "$label lacks required secure DANE"
      [[ "$TLSA_MATCH" != 1 || "$pkix_ok" == true ]] || fail "$label usage 1 requires PKIX"
      ;;
  esac
}

probe_host_meta_address() {
  local ip="$1" port="$2" sni="$3" pins_csv="$4"
  local connect label tls_flag version_args transcript leaf chain pkix_ok=false identity_ok=false pin_ok=false pin
  connect="$(connect_literal "$ip" "$port")"
  label="XEP-0487 $sni:$port via $ip"
  for tls_flag in tls1_2 tls1_3; do
    [[ "$tls_flag" == tls1_2 ]] && version_args=(-tls1_2) || version_args=(-tls1_3)
    transcript="$runtime_dir/host-meta-${port}-${ip//:/_}-${tls_flag}.txt"
    if ! timeout 25 openssl s_client -connect "$connect" -servername "$sni" \
      -alpn xmpp-server "${version_args[@]}" -showcerts </dev/null >"$transcript" 2>&1; then
      fail "$label did not complete a $tls_flag handshake"
      continue
    fi
    if ! grep -Fq 'ALPN protocol: xmpp-server' "$transcript"; then
      fail "$label did not select Direct TLS ALPN xmpp-server"
    else
      pass "$label negotiated $tls_flag with xmpp-server ALPN"
    fi
  done
  transcript="$runtime_dir/host-meta-${port}-${ip//:/_}-certificate.txt"
  timeout 25 openssl s_client -connect "$connect" -servername "$sni" -alpn xmpp-server \
    -showcerts </dev/null >"$transcript" 2>&1 || true
  leaf="$runtime_dir/host-meta-${port}-${ip//:/_}-leaf.pem"
  if ! extract_leaf "$transcript" "$leaf"; then
    fail "$label did not present a parseable X.509 leaf"
    return
  fi
  chain="$runtime_dir/host-meta-${port}-${ip//:/_}-chain.pem"
  extract_chain "$transcript" "$chain" || fail "$label certificate chain could not be extracted"
  strong_leaf_key "$leaf" || fail "$label uses a weak or unsupported certificate key/signature"
  if timeout 25 openssl s_client -connect "$connect" -servername "$sni" -alpn xmpp-server \
    -verify_return_error </dev/null \
    >"$runtime_dir/host-meta-${port}-${ip//:/_}-pkix.txt" 2>&1; then
    pkix_ok=true
  fi
  if xmpp_certificate_identity "$leaf" "$domain" \
    || xmpp_certificate_identity "$leaf" "$sni"; then
    identity_ok=true
  fi
  if [[ -n "$pins_csv" ]]; then
    presented_pin="$(openssl x509 -in "$leaf" -pubkey -noout \
      | openssl pkey -pubin -outform DER \
      | openssl dgst -sha256 -binary \
      | openssl base64 -A)"
    IFS=',' read -r -a expected_pins <<<"$pins_csv"
    for pin in "${expected_pins[@]}"; do
      if [[ "$pin" == "$presented_pin" ]]; then pin_ok=true; fi
    done
  fi
  if [[ "$pkix_ok" == true && "$identity_ok" == true ]]; then
    pass "$label passed authenticated SNI delegation and certificate identity"
  elif [[ "$pin_ok" == true ]] && openssl x509 -in "$leaf" -noout -checkend 0 >/dev/null 2>&1; then
    pass "$label matched an authenticated XEP-0487 SPKI pin"
  else
    fail "$label has neither valid delegated PKIX identity nor a matching live SPKI pin"
  fi
  if [[ "$external_enabled" == true ]] \
    && ! openssl verify -purpose sslclient -untrusted "$chain" "$leaf" >/dev/null 2>&1; then
    fail "$label chain is not valid for TLS client authentication while SASL EXTERNAL is enabled"
  fi
}

endpoint_count=0
published_srv=0
usable_endpoint=0
probe_srv_method() {
  local owner="$1" method="$2"
  local srv_status line priority weight port target address_status addresses ip
  dns_query "$owner" SRV
  srv_status="$DNS_STATUS"
  [[ "$srv_status" != bogus && "$srv_status" != indeterminate ]] || fail "$owner validation is $srv_status"
  [[ -n "$DNS_RECORDS" ]] || return
  published_srv=1
  while read -r priority weight port target extra; do
    [[ -n "${priority:-}" ]] || continue
    if [[ -n "${extra:-}" || ! "$priority" =~ ^[0-9]+$ || ! "$weight" =~ ^[0-9]+$ || ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] \
      || (( priority > 65535 || weight > 65535 || port > 65535 )); then
      fail "$owner contains a malformed SRV record"
      continue
    fi
    if [[ "$target" == "." ]]; then
      warn "$owner explicitly disables this transport"
      continue
    fi
    target="${target%.}"
    addresses=""
    for address_type in A AAAA; do
      dns_query "$target" "$address_type"
      address_status="$DNS_STATUS"
      if [[ "$address_status" == bogus || "$address_status" == indeterminate ]]; then
        fail "$target $address_type validation is $address_status"
      fi
      while read -r resolved_ip extra_ip; do
        [[ -n "${resolved_ip:-}" ]] || continue
        addresses+=$'\n'"$resolved_ip $address_status"
      done <<<"$DNS_RECORDS"
    done
    addresses="$(sed '/^[[:space:]]*$/d' <<<"$addresses" | sort -u)"
    if [[ -z "$addresses" ]]; then
      fail "$owner target $target has no A/AAAA address"
      continue
    fi
    while read -r ip ip_dns_status extra_ip; do
      [[ -n "${ip:-}" ]] || continue
      if [[ -n "${extra_ip:-}" || -z "${ip_dns_status:-}" ]] || ! is_global_ip "$ip"; then
        fail "$owner selected non-public or malformed address $ip"
        continue
      fi
      endpoint_count=$((endpoint_count + 1))
      if (( endpoint_count > max_endpoints )); then
        fail "published federation endpoints exceed the preflight limit $max_endpoints"
        return
      fi
      usable_endpoint=1
      probe_tls_address "$method" "$target" "$port" "$ip" "$domain" "$srv_status" "$ip_dns_status"
    done <<<"$addresses"
  done <<<"$DNS_RECORDS"
}

echo "Northstar public federation preflight: domain=$domain dane=$dane_mode external=$external_enabled"
probe_srv_method "_xmpps-server._tcp.$domain" direct
probe_srv_method "_xmpp-server._tcp.$domain" starttls

if (( usable_endpoint == 0 )); then
  if (( published_srv != 0 )); then
    fail "SRV intent was published but no usable S2S endpoint exists; A/AAAA fallback is forbidden"
  elif [[ "$dane_mode" == required ]]; then
    fail "DANE required mode needs an authenticated XMPP SRV relationship"
  else
    dns_query "$domain" A
    fallback_addresses="$DNS_RECORDS"
    dns_query "$domain" AAAA
    fallback_addresses+=$'\n'"$DNS_RECORDS"
    fallback_addresses="$(sed '/^[[:space:]]*$/d' <<<"$fallback_addresses" | sort -u)"
    if [[ -z "$fallback_addresses" ]]; then
      fail "$domain has neither S2S SRV endpoints nor an A/AAAA fallback"
    else
      while read -r ip; do
        is_global_ip "$ip" || { fail "implicit S2S fallback is not public: $ip"; continue; }
        probe_tls_address starttls "$domain" 5269 "$ip" "$domain" absent absent
      done <<<"$fallback_addresses"
    fi
  fi
fi

host_meta_headers="$runtime_dir/host-meta.headers"
host_meta_body="$runtime_dir/host-meta.json"
host_meta_endpoints="$runtime_dir/host-meta.endpoints"
if timeout 25 curl --silent --show-error --fail --proto '=https' --tlsv1.2 \
  --max-redirs 3 --max-time 20 -D "$host_meta_headers" -o "$host_meta_body" \
  "https://$domain/.well-known/host-meta.json"; then
  content_type="$(awk 'BEGIN{IGNORECASE=1} /^content-type:/{value=$0} END{sub(/^[^:]*:[[:space:]]*/,"",value); sub(/\r$/,"",value); print tolower(value)}' "$host_meta_headers")"
  case "$content_type" in application/json*|application/jrd+json*) ;; *) fail "host-meta.json has unsupported Content-Type ${content_type:-missing}" ;; esac
  if python3 - "$host_meta_body" "$domain" "$require_xep_0487" "$host_meta_endpoints" <<'PY'
import base64, ipaddress, json, re, sys
path, domain, required, endpoint_path = sys.argv[1:]
def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member {key!r}")
        value[key] = item
    return value
with open(path, "r", encoding="utf-8") as source:
    document = json.load(source, object_pairs_hook=unique)
if not isinstance(document, dict) or not isinstance(document.get("links"), list):
    raise SystemExit("host-meta root or links member is invalid")
xmpp = document.get("xmpp")
if xmpp is None:
    if required == "true":
        raise SystemExit("XEP-0487 xmpp marker is required but absent")
    open(endpoint_path, "w", encoding="utf-8").close()
    print("legacy")
    raise SystemExit(0)
if not isinstance(xmpp, dict) or not isinstance(xmpp.get("ttl"), int) or not 1 <= xmpp["ttl"] <= 604800:
    raise SystemExit("XEP-0487 ttl is invalid")
pins = xmpp.get("public-key-pins-sha-256", [])
if not isinstance(pins, list) or len(pins) > 16:
    raise SystemExit("XEP-0487 pin list is invalid")
for pin in pins:
    if not isinstance(pin, str) or len(base64.b64decode(pin, validate=True)) != 32:
        raise SystemExit("XEP-0487 contains an invalid SPKI pin")
endpoints = 0
rows = []
for link in document["links"]:
    if not isinstance(link, dict) or link.get("rel") != "urn:xmpp:alt-connections:s2s-tls":
        continue
    port, sni, ips = link.get("port"), link.get("sni"), link.get("ips")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise SystemExit("XEP-0487 endpoint port is invalid")
    if not isinstance(sni, str) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", sni):
        raise SystemExit("XEP-0487 endpoint SNI is invalid")
    if not isinstance(ips, list) or not 1 <= len(ips) <= 32:
        raise SystemExit("XEP-0487 endpoint IP list is invalid")
    for value in ips:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise SystemExit("XEP-0487 endpoint is not globally routable")
        endpoints += 1
        rows.append(f"{address}\t{port}\t{sni.rstrip('.').lower()}\t{','.join(pins)}")
if endpoints == 0:
    raise SystemExit("authoritative XEP-0487 document has no S2S TLS endpoint")
with open(endpoint_path, "w", encoding="utf-8") as output:
    output.write("\n".join(rows) + "\n")
print(f"authoritative:{endpoints}")
PY
  then
    host_meta_kind="$(python3 -c 'import json,sys; print("authoritative" if "xmpp" in json.load(open(sys.argv[1], encoding="utf-8")) else "legacy")' "$host_meta_body")"
    pass "WebPKI-authenticated host-meta.json is structurally valid ($host_meta_kind)"
    if [[ "$host_meta_kind" == authoritative ]]; then
      host_meta_count=0
      while IFS=$'\t' read -r endpoint_ip endpoint_port endpoint_sni endpoint_pins; do
        [[ -n "${endpoint_ip:-}" ]] || continue
        host_meta_count=$((host_meta_count + 1))
        if (( host_meta_count > max_endpoints )); then
          fail "XEP-0487 live endpoints exceed the preflight limit $max_endpoints"
          break
        fi
        probe_host_meta_address "$endpoint_ip" "$endpoint_port" "$endpoint_sni" "$endpoint_pins"
      done <"$host_meta_endpoints"
    fi
  else
    fail "WebPKI-authenticated host-meta.json is invalid or unsafe"
  fi
else
  if [[ "$require_xep_0487" == true ]]; then
    fail "required HTTPS host-meta.json is unreachable"
  else
    warn "HTTPS host-meta.json is unavailable; DNS federation remains the only verified path"
  fi
fi

if (( failures != 0 )); then
  echo "external federation preflight failed: passes=$passes warnings=$warnings failures=$failures" >&2
  exit 1
fi
echo "external federation preflight passed: passes=$passes warnings=$warnings failures=0"
