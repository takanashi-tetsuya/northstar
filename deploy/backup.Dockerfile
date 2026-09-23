FROM rust:1.97.1-bookworm@sha256:14bc9c5966e7b3a385794b3d5389a8765668342025fbcc7b2e3d2866ac4bd8c3 AS builder
RUN rustc --version | grep -E '^rustc 1\.97\.1 '
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY crates ./crates
COPY services ./services
COPY tools ./tools
COPY src ./src
COPY migrations ./migrations
COPY docs/openapi.yaml ./docs/openapi.yaml
COPY deploy/postgres-init/lib/northstar-capability-manifest.sql \
     deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql \
     ./deploy/postgres-init/lib/
RUN cargo build -p rust-xmpp-server --release --locked

FROM docker.io/library/postgres:17-bookworm@sha256:84560e3b9c6874893fc4e2854f5dc3e7c1a37bc9d1dfd7a8c641310ae22ba5ad

ARG NORTHSTAR_VERSION=0.2.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Northstar Backup Utility" \
      org.opencontainers.image.description="Signed and encrypted Northstar backup utility" \
      org.opencontainers.image.version="${NORTHSTAR_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/takanashi-tetsuya/northstar" \
      org.opencontainers.image.documentation="https://github.com/takanashi-tetsuya/northstar/blob/main/docs/BACKUP_SECURITY.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apt-get update \
    && apt-get install -y --no-install-recommends age bash coreutils openssl tar gzip python3 util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 northstar \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin northstar \
    && mkdir -p /opt/northstar /opt/deploy/postgres-init/lib /uploads /rollback /state /scratch \
    && printf '%s\n' 'northstar-upload-root-v1' > /uploads/.northstar-upload-root \
    && printf '%s\n' 'northstar-restore-rollback-v1' > /rollback/.northstar-rollback-root \
    && chown -R 10001:10001 /opt/northstar /uploads /rollback /state /scratch \
    && chmod 0700 /uploads /rollback /state /scratch \
    && chmod 0600 /uploads/.northstar-upload-root /rollback/.northstar-rollback-root
COPY --chown=10001:10001 --chmod=0555 scripts/backup.sh scripts/verify-backup.sh scripts/restore-backup.sh scripts/recover-restore.sh scripts/restore-recovery.py scripts/validate-backup-dump-local.sh scripts/run-postgres.py scripts/verify-upload-archive.py scripts/backup-security.py scripts/backup-security-offline.sh /opt/northstar/
COPY --from=builder --chmod=0555 /app/target/release/rust-xmpp-server /usr/local/bin/xmpp-server
COPY --chown=10001:10001 --chmod=0555 scripts/backup-inventory.py /opt/northstar/
COPY --chown=10001:10001 --chmod=0444 \
    deploy/postgres-init/lib/reconcile-northstar-grants.sql \
    deploy/postgres-init/lib/verify-northstar-grant-boundary.sql \
    deploy/postgres-init/lib/apply-northstar-grants.sql \
    deploy/postgres-init/lib/northstar-capability-manifest.sql \
    deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql \
    deploy/postgres-init/lib/ensure-northstar-restore-outcome-marker.sql \
    /opt/deploy/postgres-init/lib/
COPY --chown=10001:10001 --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/northstar/
RUN chmod 0755 /usr/share/licenses /usr/share/licenses/northstar

USER 10001:10001
ENTRYPOINT ["bash", "/opt/northstar/backup.sh"]
