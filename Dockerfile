FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl wget git \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------
# Install Syft (latest)
# ----------------------------
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ----------------------------
# Install Trivy (latest)
# ----------------------------
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ----------------------------
# Copy project & install
# ----------------------------
WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

ENTRYPOINT ["sbom-tm"]
CMD ["--help"]
