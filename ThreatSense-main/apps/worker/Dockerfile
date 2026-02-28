FROM python:3.12-slim

WORKDIR /worker

# Install nuclei via go (avoids GitHub zip download issues)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip git golang \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    go version; \
    GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    /usr/local/bin/nuclei -version || true

# Install nuclei templates
RUN mkdir -p /opt/nuclei-templates \
    && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=INFO"]
