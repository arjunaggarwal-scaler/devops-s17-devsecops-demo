# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Stage 1 - builder: install pinned dependencies into an isolated virtualenv
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-virtualenv -r requirements.txt \
 # pip is not needed at runtime - removing it shrinks the attack surface
 && /opt/venv/bin/pip uninstall -y pip

# ---------------------------------------------------------------------------
# Stage 2 - runtime: minimal image, non-root user, no build tools
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ARG GIT_SHA=dev
LABEL org.opencontainers.image.title="devops-s17-devsecops-demo" \
      org.opencontainers.image.description="Session 17 DevSecOps demo Flask app" \
      org.opencontainers.image.source="https://github.com/arjunaggarwal-scaler/devops-s17-devsecops-demo" \
      org.opencontainers.image.revision="${GIT_SHA}"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GIT_SHA=${GIT_SHA}

# Remove the system pip (not needed at runtime) and create an unprivileged user
RUN python -m pip uninstall -y pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
# Code stays owned by root (read-only for the app user)
COPY app ./app

USER 10001:10001
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5001/health', timeout=2).status == 200 else 1)"]

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--worker-tmp-dir", "/tmp", \
     "--access-logfile", "-", "--error-logfile", "-", "app.app:app"]
