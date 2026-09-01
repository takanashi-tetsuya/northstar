#!/usr/bin/env sh
set -eu
set +x

certificate_path=${1:?usage: verify-production-certificate.sh CERTIFICATE PRIVATE_KEY DOMAIN [CA_FILE]}
private_key_path=${2:?usage: verify-production-certificate.sh CERTIFICATE PRIVATE_KEY DOMAIN [CA_FILE]}
domain=${3:?usage: verify-production-certificate.sh CERTIFICATE PRIVATE_KEY DOMAIN [CA_FILE]}
ca_file=${4:-}

fail() {
    echo "production TLS validation failed: $*" >&2
    exit 1
}

command -v openssl >/dev/null 2>&1 || fail "OpenSSL is required"
for path in "$certificate_path" "$private_key_path"; do
    [ -f "$path" ] || fail "a TLS input is missing or is not a regular file"
    [ ! -L "$path" ] || fail "TLS inputs must not be symbolic links"
done
[ -z "$ca_file" ] || {
    [ -f "$ca_file" ] || fail "the explicit CA file is missing or not a regular file"
    [ ! -L "$ca_file" ] || fail "the explicit CA file must not be a symbolic link"
    ca_size=$(stat -c '%s' "$ca_file")
    [ "$ca_size" -gt 0 ] && [ "$ca_size" -le 1048576 ] \
        || fail "the explicit CA file must be between 1 byte and 1 MiB"
    ca_mode=$(stat -c '%a' "$ca_file")
    ca_permissions=$((0$ca_mode))
    [ $((ca_permissions & 0022)) -eq 0 ] \
        || fail "the explicit CA file must not be group/world writable"
    ca_begin_count=$(grep -Ec '^-----BEGIN CERTIFICATE-----$' "$ca_file" || true)
    ca_end_count=$(grep -Ec '^-----END CERTIFICATE-----$' "$ca_file" || true)
    [ "$ca_begin_count" -ge 1 ] \
        && [ "$ca_begin_count" -le 8 ] \
        && [ "$ca_begin_count" -eq "$ca_end_count" ] \
        || fail "the explicit CA file must contain one to eight complete certificate PEM blocks"
    if grep '^-----BEGIN ' "$ca_file" | grep -Fv -- '-----BEGIN CERTIFICATE-----' >/dev/null; then
        fail "the explicit CA file contains a non-certificate PEM block"
    fi
}

certificate_size=$(stat -c '%s' "$certificate_path")
private_key_size=$(stat -c '%s' "$private_key_path")
[ "$certificate_size" -gt 0 ] && [ "$certificate_size" -le 1048576 ] \
    || fail "the certificate file must be between 1 byte and 1 MiB"
[ "$private_key_size" -gt 0 ] && [ "$private_key_size" -le 131072 ] \
    || fail "the private-key file must be between 1 byte and 128 KiB"

certificate_begin_count=$(grep -Ec '^-----BEGIN CERTIFICATE-----$' "$certificate_path" || true)
certificate_end_count=$(grep -Ec '^-----END CERTIFICATE-----$' "$certificate_path" || true)
[ "$certificate_begin_count" -ge 1 ] \
    && [ "$certificate_begin_count" -le 8 ] \
    && [ "$certificate_begin_count" -eq "$certificate_end_count" ] \
    || fail "the certificate file must contain one to eight complete certificate PEM blocks"
if grep -Eq '^-----BEGIN .*PRIVATE KEY-----$|^-----BEGIN ENCRYPTED PRIVATE KEY-----$' "$certificate_path"; then
    fail "the certificate file contains private-key material"
fi
if grep '^-----BEGIN ' "$certificate_path" | grep -Fv -- '-----BEGIN CERTIFICATE-----' >/dev/null; then
    fail "the certificate file contains a non-certificate PEM block"
fi

private_key_begin_count=$(grep -Ec '^-----BEGIN (RSA |EC )?PRIVATE KEY-----$' "$private_key_path" || true)
[ "$private_key_begin_count" -eq 1 ] \
    || fail "the key file must contain exactly one unencrypted private-key PEM block"
if grep -Eq '^-----BEGIN CERTIFICATE-----$|^-----BEGIN ENCRYPTED PRIVATE KEY-----$' "$private_key_path"; then
    fail "the key file contains a certificate or encrypted key"
fi
if grep '^-----BEGIN ' "$private_key_path" \
    | grep -Ev -- '^-----BEGIN (RSA |EC )?PRIVATE KEY-----$' >/dev/null; then
    fail "the key file contains an unsupported PEM block"
fi

certificate_mode=$(stat -c '%a' "$certificate_path")
certificate_permissions=$((0$certificate_mode))
[ $((certificate_permissions & 0022)) -eq 0 ] \
    || fail "the certificate file must not be group/world writable"
private_key_mode=$(stat -c '%a' "$private_key_path")
case "$private_key_mode" in
    400|600) ;;
    *) fail "the TLS private key permissions must be exactly 0400 or 0600" ;;
esac

openssl x509 -in "$certificate_path" -noout >/dev/null 2>&1 \
    || fail "the certificate is not valid PEM X.509 data"
# An empty passphrase makes encrypted keys fail immediately instead of opening
# an interactive prompt in a release job.
openssl pkey -in "$private_key_path" -passin pass: -check -noout >/dev/null 2>&1 \
    || fail "the private key is invalid, encrypted, or internally inconsistent"

openssl x509 -in "$certificate_path" -noout -checkend 2592000 >/dev/null \
    || fail "the certificate expires within 30 days"
openssl x509 -in "$certificate_path" -noout -text \
    | grep -Eq 'Version:[[:space:]]*3' \
    || fail "the leaf certificate must be X.509 version 3"
subject_alternative_name=$(openssl x509 -in "$certificate_path" -noout -ext subjectAltName 2>/dev/null || true)
echo "$subject_alternative_name" | grep -F 'X509v3 Subject Alternative Name' >/dev/null \
    || fail "the TLS leaf certificate must contain a Subject Alternative Name extension"
openssl x509 -in "$certificate_path" -noout -checkhost "$domain" >/dev/null \
    || fail "the certificate Subject Alternative Name does not cover XMPP_DOMAIN"

basic_constraints=$(openssl x509 -in "$certificate_path" -noout -ext basicConstraints 2>/dev/null || true)
echo "$basic_constraints" | grep -F 'CA:FALSE' >/dev/null \
    || fail "the TLS leaf certificate must explicitly declare CA:FALSE"
key_usage=$(openssl x509 -in "$certificate_path" -noout -ext keyUsage 2>/dev/null || true)
echo "$key_usage" | grep -F 'Digital Signature' >/dev/null \
    || fail "the TLS leaf key usage must permit digital signatures"
echo "$key_usage" | grep -Eq 'Certificate Sign|CRL Sign' \
    && fail "the TLS leaf key usage must not permit CA signing"
extended_key_usage=$(openssl x509 -in "$certificate_path" -noout -ext extendedKeyUsage 2>/dev/null || true)
echo "$extended_key_usage" | grep -F 'TLS Web Server Authentication' >/dev/null \
    || fail "the TLS leaf extended key usage must permit server authentication"

subject=$(openssl x509 -in "$certificate_path" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
issuer=$(openssl x509 -in "$certificate_path" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
[ "$subject" != "$issuer" ] || fail "a production TLS certificate must not be self-signed"

signature_algorithm=$(openssl x509 -in "$certificate_path" -noout -text \
    | sed -n 's/^[[:space:]]*Signature Algorithm: //p' | head -n 1)
case "$signature_algorithm" in
    *md2*|*MD2*|*md5*|*MD5*|*sha1*|*SHA1*) fail "the certificate uses an obsolete signature" ;;
esac

public_key_algorithm=$(openssl x509 -in "$certificate_path" -noout -text \
    | sed -n 's/^[[:space:]]*Public Key Algorithm: //p' | head -n 1)
public_key_bits=$(openssl x509 -in "$certificate_path" -pubkey -noout \
    | openssl pkey -pubin -text -noout \
    | sed -n 's/^Public-Key: (\([0-9][0-9]*\) bit)$/\1/p' | head -n 1)
case "$public_key_algorithm" in
    rsaEncryption)
        [ -n "$public_key_bits" ] && [ "$public_key_bits" -ge 3072 ] \
            || fail "RSA TLS keys must be at least 3072 bits"
        ;;
    id-ecPublicKey)
        [ -n "$public_key_bits" ] && [ "$public_key_bits" -ge 256 ] \
            || fail "ECDSA TLS keys must be at least 256 bits"
        ;;
    *) fail "the TLS public-key algorithm is unsupported by RFC 5929 channel binding" ;;
esac

certificate_key_hash=$(openssl x509 -in "$certificate_path" -pubkey -noout | openssl sha256)
private_key_hash=$(openssl pkey -in "$private_key_path" -passin pass: -pubout | openssl sha256)
[ "$certificate_key_hash" = "$private_key_hash" ] \
    || fail "the TLS certificate and private key do not match"

if [ -n "$ca_file" ]; then
    openssl verify -x509_strict -purpose sslserver -verify_hostname "$domain" \
        -CAfile "$ca_file" -untrusted "$certificate_path" "$certificate_path" >/dev/null 2>&1 \
        || fail "the certificate does not build a trusted server-authentication chain"
else
    openssl verify -x509_strict -purpose sslserver -verify_hostname "$domain" \
        -untrusted "$certificate_path" "$certificate_path" >/dev/null 2>&1 \
        || fail "the certificate does not build a system-trusted server-authentication chain"
fi

echo "production TLS certificate validation passed"
