# Build stage
FROM rust:1.82 as builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo build --release

# Runtime stage — koristi OS koji ima istu verziju glibc kao build stage!
FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/target/release/statuspulse .

EXPOSE 3000
CMD ["./statuspulse"]
