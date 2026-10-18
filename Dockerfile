# API image. Dependencies go into a virtualenv at /opt/venv (not /root/.local),
# so the non-root runtime user can actually import them.
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY harnis ./harnis
RUN pip install ".[k8s]"

FROM python:3.12-slim AS runtime
ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
COPY LICENSE NOTICE /usr/share/doc/harnis/
WORKDIR /app
# Owned by the app user so the named `workspaces` volume inherits that owner.
RUN mkdir -p /app/.workspaces && chown app:app /app/.workspaces
USER app
EXPOSE 8000
# No curl in slim images; use Python for the health check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"
CMD ["uvicorn", "harnis.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
