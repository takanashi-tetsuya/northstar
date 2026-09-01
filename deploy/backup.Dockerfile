FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73

ARG NORTHSTAR_VERSION=1.1.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Northstar Backup Utility" \
      org.opencontainers.image.description="Signed and encrypted Northstar backup utility" \
      org.opencontainers.image.version="${NORTHSTAR_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/takanashi-tetsuya/northstar" \
      org.opencontainers.image.documentation="https://github.com/takanashi-tetsuya/northstar/blob/main/docs/BACKUP_SECURITY.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apk add --no-cache age bash coreutils openssl tar gzip python3 util-linux \
    && addgroup -S -g 10001 northstar \
    && adduser -S -D -H -u 10001 -G northstar northstar \
    && mkdir -p /opt/northstar /opt/deploy/postgres-init/lib /uploads /rollback /state /scratch \
    && printf '%s\n' 'northstar-upload-root-v1' > /uploads/.northstar-upload-root \
    && printf '%s\n' 'northstar-restore-rollback-v1' > /rollback/.northstar-rollback-root \
    && chown -R 10001:10001 /opt/northstar /uploads /rollback /state /scratch \
    && chmod 0700 /uploads /rollback /state /scratch \
    && chmod 0600 /uploads/.northstar-upload-root /rollback/.northstar-rollback-root
COPY --chown=10001:10001 --chmod=0555 scripts/backup.sh scripts/verify-backup.sh scripts/restore-backup.sh scripts/validate-backup-dump-local.sh scripts/run-postgres.py scripts/verify-upload-archive.py scripts/backup-security.py scripts/backup-security-offline.sh /opt/northstar/
COPY --chown=10001:10001 --chmod=0444 \
    deploy/postgres-init/lib/verify-northstar-grant-boundary.sql \
    deploy/postgres-init/lib/apply-northstar-grants.sql \
    deploy/postgres-init/lib/northstar-capability-manifest.sql \
    deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql \
    /opt/deploy/postgres-init/lib/
COPY --chown=10001:10001 --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/northstar/

USER 10001:10001
ENTRYPOINT ["bash", "/opt/northstar/backup.sh"]
