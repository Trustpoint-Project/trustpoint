FROM python:3.12-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:0.6.17 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_FROZEN=1

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443

# Update apt repository and install required dependencies from apt
RUN apt-get update && \
    apt-get upgrade -y && \
        apt-get install -y --no-install-recommends \ 
        sudo \
        apt-utils \
        apache2 \
        apache2-utils \
        gettext \
        apache2-dev && \
    rm -rf /var/lib/apt/lists/*

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
        git clone -b "${BRANCH}" https://github.com/TrustPoint-Project/trustpoint.git /var/www/html/trustpoint/; \
        apt remove -y git; \
    fi && \
    chmod 755 /var/www/html/trustpoint/ && \
    chown www-data:www-data /var/www/html/trustpoint/

USER www-data
RUN uv sync --python-preference only-system --python 3.12
RUN uv pip install --upgrade pip && uv pip install mod_wsgi
USER root

RUN uv run mod_wsgi-express install-module \
    > /etc/apache2/mods-available/wsgi.load && \
    a2enmod wsgi

# Sets DEBUG = False and DOCKER_CONTAINER = True in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py && \
    sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Create and setup the /etc/trustpoint/ directory
RUN mkdir -p /etc/trustpoint/ && \
    cp -r /var/www/html/trustpoint/docker/* /etc/trustpoint/ && \
    chown -R root:root /etc/trustpoint/ && \
    chmod -R 755 /etc/trustpoint/

# Add sudoers file and configure user and restart sudo service
RUN cp ./docker/wizard/sudoers /etc/sudoers && \
    chown root:root /etc/sudoers && \
    chmod 440 /etc/sudoers && \
    service sudo restart

# TODO(AlexHx8472): We may want to use proper docker secrets handling in the future
RUN mkdir -p /etc/trustpoint/secrets && \
    uv run python -c "from pathlib import Path; from django.core.management.utils import get_random_secret_key; Path('/etc/trustpoint/secrets/django_secret_key.env').write_text(get_random_secret_key())" && \
    chown -R www-data:www-data /etc/trustpoint/secrets && \
    chmod -R 700 /etc/trustpoint/secrets

# Remove any enabled Apache sites and add new Apache configuration
RUN rm -f /etc/apache2/sites-enabled/* && \
    cp ./docker/apache/trustpoint-http-init.conf /etc/apache2/sites-available/trustpoint-http-init.conf && \
    a2ensite trustpoint-http-init.conf

# Make entrypoint script executable
RUN chmod +x ./docker/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["docker/entrypoint.sh"]
