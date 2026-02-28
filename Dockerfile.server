FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y cmake gcc g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p viavless-server && strip target/release/viavless-server

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/target/release/viavless-server /viavless-server

EXPOSE 443 8080

ENTRYPOINT ["/viavless-server"]
