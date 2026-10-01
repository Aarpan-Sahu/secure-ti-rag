# syntax=docker/dockerfile:1.7
# Build:  docker build -f docker/Dockerfile -t tirag:local .
#
# Hardening: multi-stage (no compilers/pip cache in the runtime image), hash-verified dependency
# install, non-root numeric UID, no shell-form entrypoint, health check, no secrets baked in.
# Pin the base image by digest in CI (Dependabot's docker ecosystem keeps tag + digest current).

ARG PYTHON_IMAGE=python:3.11-slim-bookworm

# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
# 1) third-party dependencies, every artefact verified against the hashes in requirements.txt
COPY requirements.txt ./
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.txt
# 2) the application itself
COPY pyproject.toml README.md ./
COPY src ./src
RUN /opt/venv/bin/pip install --no-deps .

# ---------------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=dev
LABEL org.opencontainers.image.title="tirag" \
      org.opencontainers.image.description="Secure RAG over MISP and OpenCTI threat intelligence" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    TIRAG_ENV=prod

# Amazon RDS CA bundle so the database connection can use sslmode=verify-full.
# To pin it, add: --checksum=sha256:<digest of the bundle you reviewed>
ADD --chmod=0444 https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /etc/ssl/rds/global-bundle.pem

RUN groupadd --system --gid 10001 tirag \
 && useradd  --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin tirag

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /tmp
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]

# The listener trusts X-Forwarded-For from any peer: ONLY safe because the task security group
# admits traffic exclusively from the load balancer (see infrastructure/terraform/modules/app).
ENTRYPOINT ["tirag"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080", "--forwarded-allow-ips", "*"]
