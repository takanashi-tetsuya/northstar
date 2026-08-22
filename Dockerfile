FROM rust:bookworm AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home xmpp
WORKDIR /app
COPY --from=builder /app/target/release/rust-xmpp-server /usr/local/bin/xmpp-server
COPY migrations ./migrations
COPY web ./web
USER xmpp
EXPOSE 5222 5269 8080
ENTRYPOINT ["xmpp-server"]
