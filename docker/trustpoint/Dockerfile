FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.10.4 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_FROZEN=1 \
    PKCS11_PROXY_SOCKET=tcp://softhsm:5657

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through NGINX.
EXPOSE 80 443

# Update apt repository and install required dependencies from apt
RUN apt-get update && \
    apt-get upgrade -y && \
        apt-get install -y --no-install-recommends \
        opensc \
        sudo \
        apt-utils \
        nginx \
        gettext \
        cron \
        locales \
        postgresql-client \
        git \
        build-essential \
        cmake \
        libssl-dev \
        libseccomp-dev \
        && rm -rf /var/lib/apt/lists/*

# Clone and build pkcs11-proxy
RUN git clone https://github.com/SUNET/pkcs11-proxy.git /tmp/pkcs11-proxy && \
    cd /tmp/pkcs11-proxy && \
    mkdir build && cd build && \
    cmake .. && \
    make && \
    make install && \
    rm -rf /tmp/pkcs11-proxy

# Set locale Settings
RUN sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

# Sets the current WORKDIR for the following commands
WORKDIR /var/www/html/trustpoint/

ARG BRANCH=""
COPY --chown=www-data:www-data ./ ./

# this allows you to use an argument if you want to build a specific branch, e.g. to build the main branch:
# docker compose build --build-arg BRANCH=main
# This implicitly also works for tags and specific commits pyt providing the tag name or hash of the commit to BRANCH
RUN if [ "${BRANCH}" != "" ]; then \
        apt update -y && apt install -y git; \
        rm -rf /var/www/html/trustpoint/; \
        git clone -b "${BRANCH}" https://github.com/Trustpoint-Project/trustpoint.git /var/www/html/trustpoint/; \
        apt remove -y git; \
    fi && \
    chmod 755 /var/www/html/trustpoint/ && \
    chown www-data:www-data /var/www/html/trustpoint/

USER www-data
RUN uv sync --python-preference only-system
RUN uv pip install gunicorn[gevent]
USER root



# Sets DEBUG = False and DOCKER_CONTAINER = True in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py && \
    sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Create and setup the /etc/trustpoint/ directory
RUN mkdir -p /etc/trustpoint/ && \
    cp -r /var/www/html/trustpoint/docker/trustpoint/* /etc/trustpoint/ && \
    chown -R root:root /etc/trustpoint/ && \
    chmod -R 755 /etc/trustpoint/

# Add cron setup
RUN chmod +x /etc/trustpoint/notifications/execute_notifications.sh && \
    cp /etc/trustpoint/notifications/crontab.txt /etc/cron.d/execute_notifications && \
    chmod 0644 /etc/cron.d/execute_notifications && \
    crontab /etc/cron.d/execute_notifications && \
    touch /var/log/cron.log

# Add sudoers file and configure user and restart sudo service
RUN cp ./docker/trustpoint/wizard/sudoers /etc/sudoers && \
    chown root:root /etc/sudoers && \
    chmod 440 /etc/sudoers && \
    service sudo restart

# TODO(AlexHx8472): We may want to use proper docker secrets handling in the future
RUN mkdir -p /etc/trustpoint/secrets && \
    uv run python -c "from pathlib import Path; from django.core.management.utils import get_random_secret_key; Path('/etc/trustpoint/secrets/django_secret_key.env').write_text(get_random_secret_key())" && \
    chown -R www-data:www-data /etc/trustpoint/secrets && \
    chmod -R 700 /etc/trustpoint/secrets

# NGINX CONFIGURATION
RUN rm -f /etc/nginx/sites-enabled/*
COPY ./docker/trustpoint/nginx/trustpoint-nginx-https.conf /etc/nginx/sites-available/trustpoint
RUN chmod +x /etc/trustpoint/wizard/transition/*.sh

# Make entrypoint script executable
RUN chmod +x ./docker/trustpoint/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["docker/trustpoint/entrypoint.sh"]
