ARG RUST_VERSION=1.93.1

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY rust-toolchain.toml Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY static ./static
COPY src ./src

RUN cargo build --release --locked --bin vnts2

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/data

COPY --from=builder /build/target/release/vnts2 /usr/local/bin/vnts2

VOLUME ["/app/data"]

EXPOSE 29871/tcp
EXPOSE 29872/tcp
EXPOSE 29872/udp
EXPOSE 29873/udp

CMD ["vnts2"]
