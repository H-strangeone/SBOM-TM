FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# install build-time dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy package sources
COPY pyproject.toml setup.cfg* /app/
COPY src /app/src
COPY entrypoint.sh /app/entrypoint.sh

# Install package
RUN python -m pip install --upgrade pip setuptools wheel
RUN pip install .

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
FROM python:3.11-slim

# Install dependencies required for Syft + Trivy downloads
RUN apt-get update && apt-get install -y \
    curl wget git ca-certificates gnupg \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- Install Syft using the official installer script (resilient to release asset name changes) ---
RUN set -eux; \
    SYFT_INSTALL_URL="https://raw.githubusercontent.com/anchore/syft/main/install.sh"; \
    curl -fsSL --retry 5 --retry-delay 5 "$SYFT_INSTALL_URL" -o /tmp/syft-install.sh; \
    chmod +x /tmp/syft-install.sh; \
    # install to /usr/local/bin (installer accepts version arg, omit to install latest)
    /tmp/syft-install.sh -b /usr/local/bin || (cat /tmp/syft-install.sh && false); \
    rm -f /tmp/syft-install.sh;

# --- Install Trivy using the official installer script ---
RUN set -eux; \
    TRIVY_INSTALL_URL="https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"; \
    curl -fsSL --retry 5 --retry-delay 5 "$TRIVY_INSTALL_URL" -o /tmp/trivy-install.sh; \
    chmod +x /tmp/trivy-install.sh; \
    /tmp/trivy-install.sh -b /usr/local/bin || (cat /tmp/trivy-install.sh && false); \
    rm -f /tmp/trivy-install.sh;
WORKDIR /app

# Copy only critical files for pip install
COPY pyproject.toml .
COPY src ./src
COPY templates ./templates

# CLI entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Install your Python package (creates sbom-tm CLI)
RUN pip install --no-cache-dir .

ENTRYPOINT ["/entrypoint.sh"]
