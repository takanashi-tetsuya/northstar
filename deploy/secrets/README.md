# Runtime secrets

Do not place real secret values in source-controlled files, Dockerfiles, Compose
environment blocks, tickets, chat messages, or build logs.

This repository directory contains documentation only. Production secrets live
outside the source checkout. The default is `/etc/northstar/secrets`; Compose
uses that path unless `NORTHSTAR_SECRET_DIR` or an individual `*_HOST_FILE` /
`*_SECRET_FILE` setting selects another protected absolute path.

Create the root-owned parent first, then run the generator on the Linux host:

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
```

The generator deliberately refuses to create its parent: it verifies the
parent and all ancestors, records their inode/ownership/mode, and acquires a
root-owned single-link lock there before its first write. The parent must be a
real `root:root` mode-`0700` directory. The generated secret directory is a
real `root:root` mode-`0700` directory. Do not point this command into a user
checkout, shared directory, symbolic link, or replaceable path.

Each managed file is a mode-`0600`, single-link regular file. Existing material
is accepted only when its owner, permissions, exact generated length/format,
single-line encoding where applicable, database URL/password relationship, key
separation, and Ed25519/age public-private relationship all pass fail-closed
self-tests. The generator creates only missing material, refuses incomplete key
pairs or concurrent replacement, and never prints a value:

- `postgres_bootstrap_password`: consumed only by PostgreSQL for the dedicated
  `northstar_bootstrap` superuser; it is never mounted into an application job.
- `northstar_migrator_password`, `northstar_runtime_password`,
  `northstar_command_password`, and `northstar_backup_password`: read by the
  fresh-volume initializer to create independent `NOSUPERUSER` workload
  identities.
- `migrator_database_url`: mounted only into the one-shot migration job. Its
  role owns the Northstar schema but cannot create databases or roles.
- `runtime_database_url`: mounted only into the long-lived XMPP server. Its
  role is a non-owner with no DDL or trigger-management capability.
- `command_database_url`: also mounted into the long-lived server, but only for
  its isolated XEP-0133 command-session pool. The named role has no relation or
  sequence access and exactly eight typed session lifecycle capabilities; it
  cannot execute account mutations.
- `backup_database_url`: mounted only into the backup job. Its role has
  `SELECT`, but no write, routine-execution, object-creation, or role authority.
- `bootstrap_admin_password`: mounted only during the one-time bootstrap run.
- `grafana_admin_password`: mounted only into the optional Grafana container.
- `dialback_secret`: used to derive XEP-0185 Dialback keys; mount the same
  value on every Northstar node serving the same XMPP domain.
- `fast_token_secret`: mandatory for normal startup; derives XEP-0484 FAST
  credentials without storing token plaintext in PostgreSQL. Mount the same
  value on every node; rotating it intentionally revokes every issued FAST
  token. Process-local material exists only behind the explicit all-loopback
  development opt-in and must not be used for a persistent environment.
- `dummy_scram_secret`: independently derives account- and mechanism-specific
  dummy SCRAM credentials so a missing or unusable account performs the same
  wire exchange as a real account without exposing the FAST token authority.
  Mount the same independent value on every node. Never copy, reuse, or derive
  it from `fast_token_secret`; process-local material is allowed only by the
  separate explicit all-loopback development opt-in.
- `abuse_state_hmac_key`: independently de-identifies durable anti-abuse actor
  keys. Keep it stable across restarts/nodes and rotate with the documented
  previous-key overlap; never reuse the FAST or Dialback key.
- `api_control_secret`: encrypts durable REST replay responses and authenticates
  idempotency/pagination state. Mount the same independent value on every node;
  never reuse the FAST, anti-abuse, Dialback, or database secret.
- `metrics_bearer_token`: authenticates Prometheus to Northstar's separate
  private metrics listener. This owner-only copy is mounted into Northstar;
  never expose that listener through the public reverse proxy.
- `prometheus_metrics_bearer_token`: byte-identical copy of the preceding token
  owned by Prometheus' fixed UID/GID. Compose bind-mounted secrets cannot remap
  ownership, so the generator keeps two owner-only files instead of weakening
  either file to group/world-readable. Rotate both copies atomically.

The generator deliberately does not create any `*_previous_*` file. A previous
key is sensitive retained history, not a fresh random value: create and mount it
only during an explicit, time-bounded key rotation. If one of the two supported
previous-key files exists, the generator nevertheless validates its exact
64-hex-character format, owner, mode, link count, and separation from every
other managed capability.

To rotate the REST control-plane key without invalidating still-live encrypted
replays, move the former `api_control_secret` to the external mode-`0600`
`api_control_previous_secret`, install a newly generated current key, set
`API_CONTROL_PREVIOUS_SECRET_HOST_FILE`, and temporarily add the rotation
override:

```sh
sudo docker compose -f docker-compose.yml \
  -f deploy/docker-compose.api-control-key-rotation.yml up -d
```

Keep the previous key only for the maximum idempotency TTL (currently 24 hours),
then remove the override and securely delete the previous file.

External components are optional and therefore are not generated automatically.
For `deploy/docker-compose.components.yml`, copy
`deploy/components.example.json` to the ignored `deploy/components.json`, make
that configuration a non-symlink file owned by UID/GID `10001:10001` with mode
`0600`, create an independent 32–4096 byte `gateway_component_secret` under the
external secret root with the same ownership and mode, and reference its
container path with
`secret_file`. A component entry accepts exactly one of `secret` or
`secret_file`; the inline value is zeroized in memory but is intended only for
protected local/test configuration. Production should use the mounted file.

For rotation, create a new independent `abuse_state_hmac_key`, move the old
value to the external mode-`0600` file `abuse_state_hmac_previous_key`, set
`ABUSE_STATE_HMAC_PREVIOUS_KEY_HOST_FILE`, and increment
`ABUSE_STATE_HMAC_KEY_EPOCH` exactly once. Start Compose with both files and
`ABUSE_STATE_HMAC_RETIRE_PREVIOUS=false`:

```sh
sudo docker compose -f docker-compose.yml \
  -f deploy/docker-compose.abuse-key-rotation.yml up -d
```

After every node has the pair, set `ABUSE_STATE_HMAC_RETIRE_PREVIOUS=true` and
roll them again. This fences the old generation and starts the PostgreSQL
`retire_not_before` horizon. During overlap new nodes keep the old key primary;
the retiring rollout switches primary writes to the new key. Keep both files
for at least 30 days and until the durable-reference query in
`docs/PRODUCTION_OPERATIONS.md` reports zero. A linked offline admission may
have no expiry and therefore extend this period. Then remove the override, set
the retiring flag back to `false`, keep the same epoch/current key, roll every
node, and only then securely delete the previous file. A PostgreSQL authority
mismatch causes the security-critical worker to cancel the service within its
bounded poll window. Never reuse/decrement an epoch or edit the database key
IDs to force a mismatch through. Do not use this procedure to rotate FAST: the
two lifecycles are intentionally separate.

The generator also creates and self-tests the backup authenticity and
encryption pairs. It refuses an incomplete, non-canonical, or mismatched pair
rather than silently replacing one half. Follow `docs/BACKUP_SECURITY.md` and
keep these external files independent from every online-service secret:

- `backup_signing_ed25519.pem`: Ed25519 private key, mounted only into the
  backup job;
- `backup_signing_ed25519.pub.pem`: public verification key, mounted only into
  restore/audit jobs;
- `backup_age_recipients.txt`: one or more public age recipients, mounted only
  into the backup job; and
- `backup_age_identity.txt`: private age identity, mounted only into the
  restore job.

Private backup files used by the pinned backup image must be readable only by
UID/GID `10001:10001` (normally mode `0600`). Never solve a bind-mount ownership
failure by putting key material in Compose environment variables or by printing
it during diagnostics. The separate `backup-sequence-state` and
`restore-floor-state` volumes are not cryptographic keys, but they are trusted
anti-rollback state and must be backed up or replicated without resetting
either lineage.

The generator must run as root because Compose file-backed secrets are bind
mounts: Compose cannot remap their UID/GID. It assigns owner-only files to the
fixed users in the pinned images (`10001:10001` for Northstar, `70:70` for
PostgreSQL, and `472:0` for Grafana). If an audited image update changes one of
those identities, update the image digest and the corresponding documented
`*_SECRET_UID`/`*_SECRET_GID` override together; never make a secret
group/world-readable as a workaround.

Run production Compose commands through the rootful daemon with `sudo docker
compose` (or an equivalently audited privileged service account). An ordinary
checkout user cannot and should not traverse the mode-`0700` secret root merely
to let the Compose client inspect file-backed secrets.

Each role password must match only its corresponding database URL. Never copy
the bootstrap or migrator capability into `runtime_database_url` or
`backup_database_url`. Release preflight checks the exact roles/endpoints and
the Compose secret isolation. Existing volumes created with the former `xmpp`
PostgreSQL superuser require the stopped role-reconciliation procedure in
`docs/PRODUCTION_OPERATIONS.md`; the official image does not replay fresh-volume
init scripts for an existing `PGDATA`.
After the administrator has logged in and changed the bootstrap password,
recreate the XMPP service without `deploy/docker-compose.bootstrap.yml` and
securely delete `/etc/northstar/secrets/bootstrap_admin_password` (or the
selected external equivalent) from the host.

Keep the production TLS private key outside the project directory when practical.
Set `TLS_CERT_HOST_PATH` and `TLS_KEY_HOST_PATH` in the ignored `.env` to absolute
host paths. The Compose stack mounts only those two files, read-only, into the XMPP
container; it never mounts the test CA or the rest of `certs/`.
The mounted key must be readable by container UID/GID `10001:10001` while
remaining mode `0400` or `0600`. Do not point these settings at Certbot's
symbolic-link `live/` files; copy the selected full chain and key into protected
regular files, verify them, then use the authenticated reload endpoint.
