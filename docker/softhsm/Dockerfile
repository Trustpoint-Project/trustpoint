FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        netcat-openbsd \
        opensc \
        pkcs11-daemon \
        socat \
        softhsm2 && \
    rm -rf /var/lib/apt/lists/*

ENV TRUSTPOINT_HSM_ROOT=/var/lib/trustpoint/hsm \
    SOFTHSM2_CONF=/var/lib/trustpoint/hsm/config/softhsm2.conf \
    PKCS11_PROXY_SOCKET=tcp://softhsm:5657

WORKDIR /opt/trustpoint-softhsm
COPY docker/softhsm/ /opt/trustpoint-softhsm/

RUN chmod +x /opt/trustpoint-softhsm/entrypoint.sh /opt/trustpoint-softhsm/scripts/bootstrap_local_dev_token.sh && \
    install -d -m 0750 /var/lib/trustpoint/hsm/config && \
    install -d -m 0700 /var/lib/trustpoint/hsm/tokens

EXPOSE 5657

ENTRYPOINT ["/opt/trustpoint-softhsm/entrypoint.sh"]
