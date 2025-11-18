FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

# NEW: add entrypoint wrapper
COPY entrypoint.sh /entrypoint.sh

# Copy templates into the folder your program expects
COPY templates /usr/local/lib/python3.11/templates
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["sbom-tm", "--help"]