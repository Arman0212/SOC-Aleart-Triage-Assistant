# syntax=docker/dockerfile:1
# Nullpunkt analyst app with the pre-prepared demo shift (docs/deployment.md).
# The image never runs the model: every brief is already in data/demo/nullpunkt-demo.db.

ARG PYTHON_IMAGE=python:3.12.13-slim-trixie

# --- build: install the pinned dependencies and the package into a virtual environment ---------
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY docker/requirements.lock ./
RUN pip install -r requirements.lock
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
# Trimmed to keep the image under 500 MB (CI checks it): no installer, no bundled test suites, no
# Jupyter assets (pydeck's notebook widget; Streamlit ships its own map frontend), and no Arrow
# Flight RPC (loaded only by `import pyarrow.flight`, which nothing here uses). Bytecode is kept:
# it makes the first start after scale-to-zero faster. CI renders the app in the image to prove
# the trimmed environment still works.
RUN pip install --no-deps . \
    && pip uninstall -y pip \
    && SITE=/opt/venv/lib/python3.12/site-packages \
    && find "$SITE" -depth -type d -name tests -exec rm -rf {} + \
    && rm -rf /opt/venv/share/jupyter /opt/venv/etc/jupyter "$SITE/pydeck/nbextension/static" \
    && rm -f "$SITE"/pyarrow/libarrow_flight.so* "$SITE"/pyarrow/libarrow_python_flight.so* \
        "$SITE"/pyarrow/_flight.*.so "$SITE"/pyarrow/_pyarrow_cpp_tests.*.so

# --- runtime -------------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/var/lib/nullpunkt/nullpunkt.db \
    ACCOUNTS_DB_PATH=/var/lib/nullpunkt/accounts.db \
    DEMO_PRISTINE_DB=/app/data/demo/nullpunkt-demo.db \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --create-home --home-dir /home/app \
        --shell /usr/sbin/nologin app \
    && install -d -o app -g app /var/lib/nullpunkt

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY app/ app/
COPY .streamlit/config.toml .streamlit/config.toml
COPY configs/pipeline.yaml configs/pipeline.yaml
COPY data/demo/nullpunkt-demo.db data/demo/nullpunkt-demo.db
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint

LABEL org.opencontainers.image.title="nullpunkt" \
      org.opencontainers.image.description="SOC alert triage: 3,000 alerts to ranked, briefed incidents" \
      org.opencontainers.image.source="https://github.com/Arman0212/nullpunkt" \
      org.opencontainers.image.licenses="MIT"

USER app
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"]
ENTRYPOINT ["/usr/local/bin/entrypoint"]
