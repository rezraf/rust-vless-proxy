FROM rust:1.83-slim AS builder

RUN apt-get update && apt-get install -y cmake gcc g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p viavless-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/viavless-server /usr/local/bin/viavless-server

EXPOSE 443

ENTRYPOINT ["viavless-server"]
