FROM rust:1.77 as builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo build --release

# runtime
FROM debian:buster-slim

WORKDIR /app
COPY --from=builder /app/target/release/statuspulse .

CMD ["./statuspulse"]
