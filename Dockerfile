FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /work

# Install OS deps
RUN apt-get update && apt-get install -y \
    curl wget git jq \
    && rm -rf /var/lib/apt/lists/*

# Install Syft
RUN set -eux; \
    curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh -o /tmp/syft-install.sh; \
    chmod +x /tmp/syft-install.sh; \
    /tmp/syft-install.sh -b /usr/local/bin; \
    rm -f /tmp/syft-install.sh

# Install Trivy
RUN set -eux; \
    curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh -o /tmp/trivy-install.sh; \
    chmod +x /tmp/trivy-install.sh; \
    /tmp/trivy-install.sh -b /usr/local/bin; \
    rm -f /tmp/trivy-install.sh

# Copy project files
COPY pyproject.toml ./
COPY src ./src
COPY entrypoint.sh /entrypoint.sh

# Install Python package
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
