FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /work

# Install OS deps: git (for --git), curl/wget/gnupg (for Syft/Trivy installers)
RUN apt-get update && apt-get install -y \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# --- Install Syft (latest) ---
RUN set -eux; \
    SYFT_INSTALL_URL="https://raw.githubusercontent.com/anchore/syft/main/install.sh"; \
    curl -fsSL --retry 5 --retry-delay 5 "$SYFT_INSTALL_URL" -o /tmp/syft-install.sh; \
    chmod +x /tmp/syft-install.sh; \
    /tmp/syft-install.sh -b /usr/local/bin || (cat /tmp/syft-install.sh && false); \
    rm -f /tmp/syft-install.sh

# --- Install Trivy (latest) ---
RUN set -eux; \
    TRIVY_INSTALL_URL="https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"; \
    curl -fsSL --retry 5 --retry-delay 5 "$TRIVY_INSTALL_URL" -o /tmp/trivy-install.sh; \
    chmod +x /tmp/trivy-install.sh; \
    /tmp/trivy-install.sh -b /usr/local/bin || (cat /tmp/trivy-install.sh && false); \
    rm -f /tmp/trivy-install.sh

# Copy package sources
COPY pyproject.toml ./
COPY src ./src
COPY templates ./templates

# Install the Python package (installs sbom-tm console script)
RUN python -m pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
