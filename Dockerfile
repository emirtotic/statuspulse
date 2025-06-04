# ---------- Build stage ----------
FROM docker.io/library/rust:1.82-slim as builder

# Instaliraj potrebne sistemske pakete
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Postavi radni direktorijum
WORKDIR /app

# Kopiraj fajlove u kontejner
COPY . .

# Build aplikaciju u release modu
RUN cargo build --release

# ---------- Runtime stage ----------
FROM debian:bookworm-slim

# Instaliraj potrebne runtime pakete
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Postavi radni direktorijum
WORKDIR /app

# Kopiraj binarku i potrebne resurse iz build stage-a
COPY --from=builder /app/target/release/statuspulse .
COPY --from=builder /app/static ./static
COPY --from=builder /app/src/templates ./src/templates
COPY --from=builder /app/src/services/email_templates ./src/services/email_templates

# Izloži port koji koristi aplikacija
EXPOSE 3000

# Startuj aplikaciju
CMD ["./statuspulse"]
