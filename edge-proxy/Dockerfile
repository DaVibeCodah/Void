# Stage 1: Build
FROM rust:1.81-slim as builder
WORKDIR /build
RUN apt-get update && apt-get install -y \
    clang llvm libelf-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/void-edge /usr/local/bin/

EXPOSE 8080 443
ENTRYPOINT ["/usr/local/bin/void-edge"]
