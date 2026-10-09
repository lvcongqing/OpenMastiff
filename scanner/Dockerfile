ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

WORKDIR /app

ARG SYFT_VERSION=1.33.0
ARG GRYPE_VERSION=0.119.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && arch="$(uname -m)" \
    && case "$arch" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; esac \
    && rel="syft_${SYFT_VERSION}_linux_${arch}.tar.gz" \
    && (curl -fsSL --connect-timeout 15 --max-time 180 "https://ghfast.top/https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${rel}" -o /tmp/syft.tgz \
        || curl -fsSL --connect-timeout 15 --max-time 180 "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${rel}" -o /tmp/syft.tgz) \
    && tar -xzf /tmp/syft.tgz -C /usr/local/bin syft \
    && rm -f /tmp/syft.tgz \
    && grel="grype_${GRYPE_VERSION}_linux_${arch}.tar.gz" \
    && (curl -fsSL --connect-timeout 15 --max-time 180 "https://ghfast.top/https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${grel}" -o /tmp/grype.tgz \
        || curl -fsSL --connect-timeout 15 --max-time 180 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/${grel}" -o /tmp/grype.tgz) \
    && tar -xzf /tmp/grype.tgz -C /usr/local/bin grype \
    && rm -f /tmp/grype.tgz \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir bandit \
    && useradd -m scanner

COPY scanner/run_scan.sh /app/run_scan.sh
COPY scanner/detect_license.py /app/detect_license.py
COPY scanner/syft_to_license.py /app/syft_to_license.py
COPY scanner/lang_sast.py /app/lang_sast.py
COPY scanner/sca.py /app/sca.py
COPY scanner/manifest_enrich.py /app/manifest_enrich.py
COPY scanner/apply_excludes.py /app/apply_excludes.py
RUN chmod +x /app/run_scan.sh /app/detect_license.py /app/syft_to_license.py /app/lang_sast.py /app/sca.py /app/manifest_enrich.py /app/apply_excludes.py

USER scanner
ENTRYPOINT ["/app/run_scan.sh"]

