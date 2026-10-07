# Build with an independently recorded official python image digest.
# Example: docker build --build-arg BASE_IMAGE=python@sha256:<verified> ...
# The build stops unless BASE_IMAGE is pinned by digest. The reference is kept in the OCI base-image label,
# which scripts/provision-runtime.py requires before it records the worker image ID.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG BASE_IMAGE
LABEL org.opencontainers.image.base.name="${BASE_IMAGE}"
# grep prints only the matching line, so an empty or multi-line value never equals its own match.
# The runtime mounts a bounded mode-1777 tmpfs over /out, so this directory's mode is never used.
RUN [ -n "${BASE_IMAGE}" ] && [ "$(printf '%s\n' "${BASE_IMAGE}" | grep -Ex '[^@[:space:]]+@sha256:[0-9a-f]{64}')" = "${BASE_IMAGE}" ] \
    || { echo "BASE_IMAGE must be pinned by digest: <name>@sha256:<64 hex>" >&2; exit 1; } \
    && mkdir -p /inputs /out /broker /runtime /tmp/vibeaudit-inputs \
    && chmod 1777 /tmp && chmod 755 /inputs /broker /runtime && chmod 777 /out
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DO_NOT_TRACK=1 \
    LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false PROMPTFOO_DISABLE_TELEMETRY=1
USER 65533:65533
WORKDIR /tmp
ENTRYPOINT ["python3"]
