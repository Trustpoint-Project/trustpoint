FROM python:3.14-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.10.12 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_FROZEN=1 \
    PKCS11_PROXY_SOCKET=tcp://softhsm:5657

# Make port 80 and 443 available outside this container.
# 80 will be redirected to 443 using TLS through NGINX.
EXPOSE 80 443

# Update apt repository and install required dependencies
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
        git \
        build-essential \
        cmake \
        libssl-dev \
        libseccomp-dev \
        libpkcs11-proxy0 \
        curl \
        ca-certificates \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

# Install PostgreSQL 18 client
RUN curl -fSsL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt/ trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client-18 && \
    rm -rf /var/lib/apt/lists/*

# Set locale settings
RUN sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

WORKDIR /var/www/html/trustpoint/

ARG BRANCH=""
COPY --chown=www-data:www-data ./ ./

# This allows you to use an argument if you want to build a specific branch, e.g.:
# docker compose build --build-arg BRANCH=main
# This also works for tags and specific commits by providing the tag name or commit hash to BRANCH.
RUN if [ "${BRANCH}" != "" ]; then \
        apt-get update -y && apt-get install -y --no-install-recommends git; \
        rm -rf /var/www/html/trustpoint/; \
        git clone -b "${BRANCH}" https://github.com/Trustpoint-Project/trustpoint.git /var/www/html/trustpoint/; \
        apt-get remove -y git; \
        rm -rf /var/lib/apt/lists/*; \
    fi && \
    chmod 755 /var/www/html/trustpoint/ && \
    chown www-data:www-data /var/www/html/trustpoint/

USER www-data
RUN uv sync --group docs --python-preference only-system
RUN uv pip install gunicorn[gevent]
USER root

RUN mkdir -p /var/www/html/trustpoint/trustpoint/media/log \
             /var/www/html/trustpoint/trustpoint/collected_static \
             /var/www/html/trustpoint/docker/trustpoint/nginx/tls && \
    chown -R www-data:www-data /var/www/html/trustpoint/trustpoint/ && \
    chown -R www-data:www-data /var/www/html/trustpoint/docker/trustpoint/nginx/tls && \
    chmod -R 755 /var/www/html/trustpoint/trustpoint/ && \
    chmod -R 755 /var/www/html/trustpoint/docker/trustpoint/nginx/tls

# Set DEBUG = False and DOCKER_CONTAINER = True in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py && \
    sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Create and set up the /etc/trustpoint/ directory
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

# NGINX configuration
RUN rm -f /etc/nginx/sites-enabled/*
COPY ./docker/trustpoint/nginx/trustpoint-nginx-https.conf /etc/nginx/sites-available/trustpoint
RUN chmod +x /etc/trustpoint/wizard/transition/*.sh

# Make entrypoint script executable
RUN chmod +x ./docker/trustpoint/entrypoint.sh

ENTRYPOINT ["docker/trustpoint/entrypoint.sh"]
