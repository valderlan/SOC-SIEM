# Stage 3 runtime image: FastAPI SOAR webhook receiver.
# Dry-run is the default; set SOCLAB_RESPONSE_DRY_RUN=false to enable real blocks.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv sync --no-dev

ENV PATH="/app/.venv/bin:$PATH"

RUN mkdir -p /app/logs /app/runtime

EXPOSE 8080

CMD ["soclab", "run", "--host", "0.0.0.0", "--port", "8080"]
