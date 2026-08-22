# Northstar production operations

This runbook covers the single-node deployment target. It deliberately keeps
database credentials out of command-line arguments and treats PostgreSQL plus
the immutable upload store as one recoverable service state.

## Health model

- `/healthz` is a liveness probe. It answers while the HTTP process can serve.
- `/readyz` is a dependency-readiness probe and queries PostgreSQL.
- `/metrics` remains available when PostgreSQL is down. It exports
  `xmpp_database_up=0` and the measured database probe duration instead of
  failing the scrape.
- C2S, S2S, and HTTP listeners are separate tasks. If any listener exits, the
  process initiates shutdown rather than silently running a partial service.

Do not use `/healthz` as the load-balancer readiness check. Use `/readyz`.

## Metrics and alerts

The base counters cover connection totals, active client resources, stanza
traffic, authentication failures, routing, federation, abuse controls,
moderation, and PEP item activity. Runtime gauges additionally expose:

- PostgreSQL availability, probe duration, pool size, idle connections, and
  configured maximum;
- resumable Stream Management sessions and current MUC occupants;
- active inbound federation streams and outbound federation workers;
- process uptime and background-maintenance failures.

Start the optional local monitoring stack with:

```sh
bash scripts/create-production-secrets.sh
docker compose --profile monitoring up -d
```

Prometheus and Grafana bind only to host loopback by default. Publishing either
UI through Caddy requires a separate authentication and authorization decision.
The included Prometheus rules have no receiver; configure Alertmanager or a
managed alert receiver before relying on them.

## Online backup

Set `DATABASE_URL` in the environment or point to its mounted file without
putting the URL in the process list:

```sh
bash scripts/backup.sh \
  --database-url-file deploy/secrets/database_url \
  --upload-dir data/uploads \
  --output /srv/northstar-backups
```

The backup script:

1. creates a restrictive, atomic staging directory;
2. writes a PostgreSQL custom-format dump and validates its table of contents;
3. archives immutable completed upload files while excluding `.part` files;
4. records format/version metadata and SHA-256 checksums;
5. publishes the directory only after writing a `READY` marker.

`run-postgres.py` parses the URL for each PostgreSQL client, removes the URL
from the child environment, and places any password in a mode-0600 temporary
passfile. Production should prefer `--database-url-file`; the direct
`DATABASE_URL` form remains useful for local administration but may itself be
visible in the wrapper process environment on operating systems that expose it.

For the Docker Compose deployment, the same operation is wired to the named
upload volume and internal PostgreSQL network:

```sh
docker compose --profile backup run --rm backup
```

Northstar renames a complete upload into place before marking its database row
as uploaded. Completed files are immutable. Consequently, a live backup can
contain harmless extra files completed after the database snapshot, but every
`uploaded=true` row visible to the dump must already have a final file. The
restore verifier checks the stronger database-to-file direction.

Copy each completed backup off-host and encrypt it with the organization's
backup key system. The scripts intentionally do not invent or retain encryption
keys on the XMPP host. Test retention with `--retention-days` only after an
off-host copy policy is operating; that option deletes expired backup
directories beneath the exact output directory.

## Backup verification

```sh
bash scripts/verify-backup.sh /srv/northstar-backups/northstar-YYYYMMDDTHHMMSSZ
```

Verification checks the `READY` marker, format version, all hashes, PostgreSQL
archive readability, and archive path safety. Run it again after transfer to
off-host storage. A verified archive is not yet a proven recovery; schedule a
restore drill.

## Restore drill

Stop Northstar first. Restore into an isolated database and upload path whenever
possible:

```sh
bash scripts/restore-backup.sh /srv/northstar-backups/northstar-... \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file /srv/northstar-secrets/restore-database-url \
  --upload-dir /srv/northstar-restore/uploads
```

For Compose, stop `xmpp` first and pass the backup directory explicitly. The
restore service has no usable default command and still requires the same
confirmation phrase:

```sh
docker compose stop xmpp
docker compose --profile restore run --rm restore \
  /backups/northstar-YYYYMMDDTHHMMSSZ \
  --confirm-restore NORTHSTAR-RESTORE \
  --database-url-file /run/secrets/database_url \
  --upload-dir /uploads
```

The explicit phrase is required because `pg_restore --clean` replaces objects
in the target database. Existing upload files are moved to a timestamped
`pre-restore` directory rather than deleted. After restore, every database row
marked as uploaded is checked for an exact-size file.

Before returning production traffic:

1. run the server on isolated bind addresses with federation disabled;
2. verify `/readyz` and ensure migrations are current;
3. test SCRAM login, roster, PEP device lists and bundles, encrypted MAM, MUC,
   HTTP Upload, and administration;
4. decrypt sampled history with a retained client device—server backups never
   contain OMEMO private keys;
5. record recovery-point and recovery-time results.

## OMEMO multi-device operational checks

The server stores the OMEMO 2 devices node as a single `current` item and the
bundle node as multiple device-ID items. Both nodes default to open access as
required for first contact and group chat. Other PEP nodes default to presence
access. Publish-options are treated as preconditions, malformed OMEMO payloads
are rejected before an atomic batch write, and device bundle items can be
retracted. PEP headline events are addressed to each subscriber and cross the
S2S router for remote roster subscribers instead of relying on polling.

The browser client reacts to its own device-list notifications. If two devices
publish concurrently and one overwrites the other, the missing device re-reads
the list and reannounces itself, as required by XEP-0384. Consumed one-time
prekeys are replenished with new monotonically rotating IDs rather than reused
IDs. Monitor PEP publication/retraction/retrieval rates when diagnosing device
initialization.

## Release checks

Static verification remains:

```sh
bash scripts/release-preflight.sh
```

After authorization to start isolated services, run the full runtime suite. It
must include the integration PEP batch/retract/access cases, two-domain
federation, 1,000 authenticated resources, the private PostgreSQL
backup/restore drill, and three browser contexts covering two concurrent OMEMO
devices for one account plus a peer. Runtime success on a development
workstation is design evidence, not a production capacity guarantee.
