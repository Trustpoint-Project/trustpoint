FROM alpine:3.23

RUN apk add --no-cache \
    avahi \
    avahi-tools \
    dbus \
    iproute2 \
    bash

RUN mkdir -p /var/run/dbus

COPY ./docker/mdns/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]