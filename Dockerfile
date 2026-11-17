# Build from the REPOSITORY ROOT: the module depends on ../../sdk/python.
#   docker build -f modules/web/Dockerfile -t vade/web:dev .
#
# No packaging step on purpose: the image only needs the two source trees on
# PYTHONPATH plus the two runtime wheels. `pip install .` would drag a build
# backend (hatchling/setuptools) into an offline builder for no benefit — the
# module is run as `python -m web_module`, not imported from site-packages.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:/opt/vade-sdk \
    MODULE_KEY_PATH=/data/module.key \
    VADE_DATA_DIR=/data

WORKDIR /app

RUN pip install --no-cache-dir "websockets>=13" "cryptography>=42"

COPY sdk/python /opt/vade-sdk
COPY modules/web/src /app/src

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin vade \
    && mkdir -p /data && chown -R 10001:10001 /data

USER 10001:10001
VOLUME ["/data"]

# The Noise binding (vade_protocol) is not in this image: mount it at
# /opt/vade-sdk/vade_protocol.py + libvade_protocol.so, or rebuild the image
# with `protocol/core` present. Without it only --standalone works, which is
# intentional: a container that cannot authenticate must say so, not fall back.
#
# This module needs egress (that is its job). The SSRF policy is the second
# gate, not the only one: do not route internal networks to this container.
STOPSIGNAL SIGTERM
CMD ["python", "-m", "web_module", "--core", "wss://core:8443"]
