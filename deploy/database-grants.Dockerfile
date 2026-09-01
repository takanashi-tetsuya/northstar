FROM postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73

ARG NORTHSTAR_VERSION=1.1.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Northstar Database Grant Reconciler" \
      org.opencontainers.image.description="Least-privilege PostgreSQL grant reconciler for Northstar" \
      org.opencontainers.image.version="${NORTHSTAR_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/takanashi-tetsuya/northstar" \
      org.opencontainers.image.documentation="https://github.com/takanashi-tetsuya/northstar/blob/main/docs/DATABASE_ROLES.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apk add --no-cache bash python3 \
    && addgroup -S -g 10001 northstar \
    && adduser -S -D -H -u 10001 -G northstar northstar \
    && mkdir -p /workspace/scripts /workspace/deploy/postgres-init/lib /workspace/migrations \
    && chown -R 10001:10001 /workspace
WORKDIR /workspace
COPY --chown=10001:10001 --chmod=0555 \
    scripts/reconcile-database-grants.sh scripts/run-postgres.py ./scripts/
COPY --chown=10001:10001 --chmod=0444 \
    deploy/postgres-init/lib/reconcile-northstar-grants.sql \
    deploy/postgres-init/lib/verify-northstar-grant-boundary.sql \
    deploy/postgres-init/lib/apply-northstar-grants.sql \
    deploy/postgres-init/lib/northstar-capability-manifest.sql \
    deploy/postgres-init/lib/northstar-migration-ledger-manifest.sql \
    ./deploy/postgres-init/lib/
# This content is not executed here. It intentionally makes the one-shot ACL
# image change whenever the migration set changes, so a release cannot reuse a
# previously completed grants container after adding database objects.
COPY --chown=10001:10001 --chmod=0444 migrations ./migrations
COPY --chown=10001:10001 --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/northstar/

USER 10001:10001
ENTRYPOINT ["bash", "/workspace/scripts/reconcile-database-grants.sh"]
