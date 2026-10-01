# Build with an independently recorded official python image digest.
# Example: docker build --build-arg BASE_IMAGE=python@sha256:<verified> ...
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
# The runtime mounts a bounded mode-1777 tmpfs over /out, so this directory's mode is never used.
RUN mkdir -p /inputs /out /broker /runtime /tmp/vibeaudit-inputs \
    && chmod 1777 /tmp && chmod 755 /inputs /broker /runtime && chmod 777 /out
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DO_NOT_TRACK=1 \
    LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false PROMPTFOO_DISABLE_TELEMETRY=1
USER 65533:65533
WORKDIR /tmp
ENTRYPOINT ["python3"]
