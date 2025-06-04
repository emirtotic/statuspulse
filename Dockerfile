# Build stage
FROM docker.io/library/rust:1.82 as builder

WORKDIR /app
COPY . .

RUN apt-get update && apt-get install -y pkg-config libssl-dev

RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Binarni fajl
COPY --from=builder /app/target/release/statuspulse .

# Kopiraj sve potrebne resurse
COPY --from=builder /app/static ./static
COPY --from=builder /app/src/templates ./src/templates
COPY --from=builder /app/src/services/email_templates ./src/services/email_templates

EXPOSE 3000
CMD ["./statuspulse"]
