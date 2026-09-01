# Read-only identity audit

Northstar's exact RFC 7622 migration uses the same PRECIS and IDNA implementation as the protocol runtime. It deliberately refuses malformed identities and canonical collisions instead of guessing that two stored spellings belong to the same principal. `audit-identities` is the preflight tool for an old database that may not pass that migration.

The command is an offline maintenance command. It does **not** start XMPP, HTTP, federation, workers, TLS, bootstrap administration, or normal migrations.

```sh
DATABASE_URL_FILE=/run/secrets/database_url \
  /usr/local/bin/xmpp-server audit-identities --dry-run \
  --xmpp-domain example.org > identity-audit.redacted.json
```

`--dry-run` is mandatory. There is no write or automatic-repair mode. A clean report exits successfully. A report with findings is completely emitted to standard output and then exits non-zero so it can gate an upgrade. Errors and the non-sensitive final status go to standard error.

Options:

- `--xmpp-domain DOMAIN` supplies the account domain needed to verify durable session ownership. It defaults to `XMPP_DOMAIN`, then `localhost`.
- `--include-sensitive-values` places original and canonical JID/domain values in the JSON. Without it, values and scopes are replaced by salted, report-local SHA-256 fingerprints plus byte/scalar lengths.
- `--compact` emits one-line JSON.

The random fingerprint salt exists only in process memory and is not written into the report. Equal values can therefore be correlated inside one report, but not reliably across reports. This is pseudonymization, not anonymization; protect every report as operational security data. The sensitive mode should be used only in a protected terminal or an access-controlled file. Never attach an unreviewed sensitive report to an issue.

Finding locators use PostgreSQL `ctid` plus a nested-array index only to correlate rows inside the immutable audit snapshot. A `ctid` is not a durable identifier and must never be copied into a later repair statement: vacuum, update or restore can change it. Locate repair targets again by their reviewed logical key inside the isolated maintenance transaction.

## Read-only guarantee

The audit command runs before normal configuration and startup. It opens one PostgreSQL connection, sets `default_transaction_read_only=on`, and performs the scan in a `REPEATABLE READ READ ONLY` transaction. It does not run SQL migrations or identity migration code. Before rollback it verifies that PostgreSQL did not assign the transaction an XID. The process closes the pool before returning.

The command dynamically discovers the current schema. Tables or columns introduced after the database's current migration generation are recorded under `coverage.skipped_specs`; their absence does not make an old-schema audit fail. A query failure, permission problem, or inconsistent snapshot is fatal rather than silently reducing coverage.

## Coverage and privacy boundary

The scanner covers identity-bearing keys and metadata from the base schema through the current schema, including:

- account usernames, roster, block/privacy lists, pending federation presence, MAM preferences and external MUC affiliations;
- PubSub/PEP creators, publishers, affiliations, subscriptions, access arrays, digest recipients and profile ItemIDs;
- push service identities and their delivery-attempt parent graph;
- MIX channel addresses, contacts, participants, roles, allow/ban policy, PAM, nick registration, active invitations, historical identity metadata and MIX/MUC mirrors;
- XEP-0198 sessions, joined-room/directed-presence JSON, privileged command sessions and MUC destroy tombstones;
- offline/archive identity metadata, personal and MUC admission scopes, reports/evidence sender metadata, S2S targets/bounce identities and room attribution.

The report distinguishes malformed identities, non-canonical values, PRECIS canonical collisions, A-label/U-label collisions, invalid identity-container shapes, composite-key collisions, session ownership mismatches and resource/full-JID mismatches. It also emits database foreign keys and semantic reference edges needed to plan an atomic repair.

The audit deliberately never selects or serializes:

- passwords, SCRAM verifiers, bearer tokens, API keys, HMAC keys, invitation token hashes or other secrets;
- stanza/XML/message bodies, MAM content, S2S queued stanzas or SM unacknowledged stanza bytes;
- abuse evidence bodies, report descriptions or resolutions;
- PubSub, PEP or MIX payload bodies.

Two linked-content checks are therefore reported as explicit limitations: profile PEP ItemID repairs must also update the XML root ID, and MUC destroy repairs must agree with immutable operation payload JSON. Use their dedicated, content-aware repair procedure; this audit does not cross that privacy boundary.

## Safe repair workflow

1. Create a signed, encrypted backup and verify that it restores.
2. Restore it into an isolated PostgreSQL copy. Stop all Northstar processes connected to that copy.
3. Run the redacted audit and preserve its schema/coverage section.
4. If principal identification requires it, rerun with `--include-sensitive-values` only in a protected environment.
5. For each collision, determine the intended principal from authoritative account/administrative records. Never select a winner from string spelling or row age alone.
6. Apply a reviewed repair to every foreign-key and semantic edge in one transaction. Revoke stale session/token state instead of transferring it to another account.
7. Rerun the audit until it reports `clean`; rerun it once more to demonstrate idempotence.
8. Run the normal Northstar migration on the isolated copy, then audit again and execute the relevant database/protocol tests.
9. Schedule downtime, repeat the exact reviewed transaction in production, audit again, and retain before/after evidence with restricted permissions.

The JSON report is designed to support review; it is not an executable repair plan. Northstar intentionally provides no `--apply`, `--merge`, or in-place rewrite option.
