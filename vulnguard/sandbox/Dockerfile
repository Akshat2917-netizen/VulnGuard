# VulnGuard Sandbox Container
# Multi-language build environment for secure code validation.
# Run as non-root with minimal attack surface.

FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install language toolchains
RUN apt-get update && apt-get install -y --no-install-recommends \
    # C/C++
    gcc g++ make cmake \
    # Python
    python3 python3-pip python3-venv \
    # Java
    default-jdk-headless \
    # Node.js
    nodejs npm \
    # Utilities
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/sh sandbox

# Working directory
WORKDIR /workspace

# Default to non-root
USER sandbox

# Entrypoint: execute the command passed as arguments
ENTRYPOINT ["sh", "-c"]
CMD ["echo 'VulnGuard Sandbox ready'"]
