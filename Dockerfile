FROM debian:bookworm-slim
COPY --from=ghcr.io/astral-sh/uv:0.6.3 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

ENV UV_COMPILE_BYTECODE=1
ENV UV_NO_CACHE=1
ENV UV_FROZEN=1

# Make port 80 and 443 available to the world outside this container.
# 80 will be redirected to 443 using TLS through the apache.
EXPOSE 80 443

# Update apt repository and install required dependencies from apt
RUN apt update -y && apt upgrade -y && apt install -y sudo apt-utils apache2 apache2-utils gettext libapache2-mod-wsgi-py3 sed

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
    fi

RUN chmod 755 /var/www/html/trustpoint/
RUN chown www-data:www-data /var/www/html/trustpoint/

USER www-data
RUN uv sync --python-preference only-system --python 3.11.2
USER root

# Sets DEBUG = False in the Django settings
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py

# Sets DOCKER_CONTAINER = True
RUN sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Place executables in the environment at the front of the path
#ENV PATH="/var/www/html/trustpoint/.venv/bin:$PATH"

# Create and setup the /etc/trustpoint/ directory
RUN mkdir /etc/trustpoint/
RUN cp -r /var/www/html/trustpoint/docker/* /etc/trustpoint/
RUN chown -R root:root /etc/trustpoint/
RUN chmod -R 755 /etc/trustpoint/

# Add sudoers file and configure user and permissions
RUN cp ./docker/wizard/sudoers /etc/sudoers

RUN chown root:root /etc/sudoers
RUN chmod 440 /etc/sudoers
RUN service sudo restart

# TODO(AlexHx8472): User proper docker secrets handling.
RUN mkdir /etc/trustpoint/secrets
RUN uv run python -c "from pathlib import Path; from django.core.management.utils import get_random_secret_key; secret_key_path = Path('/etc/trustpoint/secrets/django_secret_key.env'); secret_key_path.write_text(get_random_secret_key());"
RUN chown -R www-data:www-data /etc/trustpoint/secrets
RUN chmod -R 700 /etc/trustpoint/secrets

# Remove any enabled apache2 sites, if any.
RUN rm -f /etc/apache2/sites-enabled/*

# Add Apache configuration
RUN cp ./docker/apache/trustpoint-http-init.conf /etc/apache2/sites-available/trustpoint-http-init.conf

# Enable the site configuration
RUN a2ensite trustpoint-http-init.conf

# Make entrypoint script executable
RUN chmod +x ./docker/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["docker/entrypoint.sh"]