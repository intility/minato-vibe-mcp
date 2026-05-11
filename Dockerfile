# Multi-stage to keep the final image small. OpenShift assigns a random
# non-root UID per pod, which works as long as /app is group-readable
# (GID 0 by default).
FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --target=/install .

FROM python:3.12-slim
WORKDIR /app

# Copy the resolved site-packages from the build stage. We keep them under
# /app so they're owned by GID 0 along with everything else.
COPY --from=build /install /app/site-packages
ENV PYTHONPATH=/app/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MINATO_VIBE_MCP_HOST=0.0.0.0 \
    MINATO_VIBE_MCP_PORT=8000

# Make /app and everything in it group-readable so any random OpenShift UID
# (which is always added to GID 0) can read it.
RUN chgrp -R 0 /app && chmod -R g=u /app

EXPOSE 8000
USER 1001
ENTRYPOINT ["python", "-m", "minato_vibe_mcp.server"]
