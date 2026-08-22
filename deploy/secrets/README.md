# Runtime secrets

Do not place real secret values in source-controlled files, Dockerfiles, Compose
environment blocks, tickets, chat messages, or build logs.

Run `bash scripts/create-production-secrets.sh` once on the Linux deployment host.
It creates the following ignored, mode-0600 files without printing their values:

- `postgres_password`: consumed only by PostgreSQL.
- `database_url`: consumed only by the XMPP server through `DATABASE_URL_FILE`.
- `bootstrap_admin_password`: mounted only during the one-time bootstrap run.

The database password embedded in `database_url` must match `postgres_password`.
After the administrator has logged in and changed the bootstrap password, recreate
the XMPP service without `deploy/docker-compose.bootstrap.yml` and securely delete
`bootstrap_admin_password` from the host.

Keep the production TLS private key outside the project directory when practical.
Set `TLS_CERT_HOST_PATH` and `TLS_KEY_HOST_PATH` in the ignored `.env` to absolute
host paths. The Compose stack mounts only those two files, read-only, into the XMPP
container; it never mounts the test CA or the rest of `certs/`.
