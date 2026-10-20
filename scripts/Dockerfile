# Containerized Hermetic Build & Verification Environment
FROM rust:1.80-bullseye

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    curl \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Add clippy and rustfmt
RUN rustup component add clippy rustfmt

WORKDIR /workspace
COPY . .

# Run format, lints, tests, and benchmarks
CMD ["bash", "scripts/verify_phase0.sh"]
