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

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
ARG NORTHSTAR_VERSION=0.2.0
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Northstar XMPP Server" \
      org.opencontainers.image.description="Standards-oriented XMPP server written in Rust" \
      org.opencontainers.image.version="${NORTHSTAR_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/takanashi-tetsuya/northstar" \
      org.opencontainers.image.documentation="https://github.com/takanashi-tetsuya/northstar/blob/main/README.md" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=builder --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN groupadd --system --gid 10001 xmpp \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin xmpp \
    && mkdir -p /app /data/uploads /data/logs \
    && printf '%s\n' 'northstar-upload-root-v1' > /data/uploads/.northstar-upload-root \
    && chown -R 10001:10001 /data \
    && chmod 0700 /data/uploads /data/logs \
    && chmod 0600 /data/uploads/.northstar-upload-root
WORKDIR /app
COPY --from=builder --chmod=0555 /app/target/release/rust-xmpp-server /usr/local/bin/xmpp-server
COPY --chmod=0555 deploy/northstar-entrypoint.sh /usr/local/bin/northstar-entrypoint
COPY web ./web
COPY third_party/swagger-ui/dist ./third_party/swagger-ui/dist
COPY third_party/swagger-ui/LICENSE third_party/swagger-ui/NOTICE ./third_party/swagger-ui/
COPY --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/northstar/
RUN chmod 0755 /usr/share/licenses /usr/share/licenses/northstar
USER 10001:10001
EXPOSE 5222 5223 5269 5270 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/xmpp-server", "--healthcheck", "127.0.0.1:8080"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/northstar-entrypoint"]
CMD ["/usr/local/bin/xmpp-server"]
