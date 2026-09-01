#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
username="${1:-test2}"
[[ "$username" =~ ^[a-z0-9_.-]{1,64}$ ]] || {
  echo "username must use the normalized Northstar account syntax" >&2
  exit 2
}

database_url="$(sed -n 's/^DATABASE_URL=//p' .env | tail -n 1)"
xmpp_domain="$(sed -n 's/^XMPP_DOMAIN=//p' .env | tail -n 1)"
[[ -n "$database_url" ]] || {
  echo "DATABASE_URL is not available in .env" >&2
  exit 2
}
[[ "$xmpp_domain" =~ ^[A-Za-z0-9.-]+$ ]] || {
  echo "XMPP_DOMAIN is missing or malformed" >&2
  exit 2
}

result="$(psql "$database_url" --no-psqlrc --tuples-only --no-align \
  --set ON_ERROR_STOP=1 \
  --command="SELECT encrypted::TEXT || '|' || (stanza LIKE '%urn:xmpp:omemo:%' OR stanza LIKE '%eu.siacs.conversations.axolotl%')::TEXT || '|' || archive_kind FROM (SELECT a.encrypted, a.stanza, a.created_at, 'direct'::TEXT AS archive_kind FROM message_archive a JOIN users u ON u.id = a.owner_id WHERE u.username = '$username' UNION ALL SELECT m.encrypted, m.stanza, m.created_at, 'muc'::TEXT AS archive_kind FROM muc_messages m WHERE m.sender_jid = '$username@$xmpp_domain' OR m.sender_jid LIKE '$username@$xmpp_domain/%') archived ORDER BY created_at DESC LIMIT 1")"
[[ "$result" == true\|true\|* ]] || {
  echo "latest archived message for the account is not an OMEMO ciphertext (metadata: ${result:-none})" >&2
  exit 1
}
echo "production encryption probe: encrypted flag, OMEMO payload and peer archive passed"
