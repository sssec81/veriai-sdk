# Stage 1: Build stage
FROM rust:1.80-slim AS builder

WORKDIR /usr/src/veriai

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration and sources
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build the verifier-service binary
RUN cargo build --release -p verifier-service --no-default-features --features real-hardware

# Stage 2: Runtime stage
FROM debian:bookworm-slim

WORKDIR /usr/local/bin

# Install runtime dependencies (like CA certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binary from build stage
COPY --from=builder /usr/src/veriai/target/release/verifier-service .

ENV PORT=8080
EXPOSE 8080

# Required at runtime:
# TRUSTED_ROOT_CERT_PATH=/run/secrets/nitro-root.pem
# EXPECTED_PCR0=<96 hex characters>

CMD ["./verifier-service"]
