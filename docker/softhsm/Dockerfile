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

RUN softhsm_lib="$(ldconfig -p | awk '/libsofthsm2\.so/ {print $NF; exit}')" && \
    if [ -z "${softhsm_lib}" ]; then softhsm_lib="/usr/lib/softhsm/libsofthsm2.so"; fi && \
    ln -sf "${softhsm_lib}" /usr/lib/libsofthsm2.so

ENV TRUSTPOINT_HSM_ROOT=/var/lib/trustpoint/hsm \
    SOFTHSM2_CONF=/var/lib/trustpoint/hsm/config/softhsm2.conf \
    PKCS11_PROXY_SOCKET=tcp://softhsm:5657

WORKDIR /opt/trustpoint-softhsm
COPY docker/softhsm/ /opt/trustpoint-softhsm/

RUN chmod +x /opt/trustpoint-softhsm/entrypoint.sh /opt/trustpoint-softhsm/scripts/bootstrap_local_dev_token.sh && \
    install -d -o 33 -g 33 -m 0755 /var/lib/trustpoint/hsm/config && \
    install -d -o 33 -g 33 -m 0700 /var/lib/trustpoint/hsm/tokens

USER 33:33

EXPOSE 5657

ENTRYPOINT ["/opt/trustpoint-softhsm/entrypoint.sh"]
