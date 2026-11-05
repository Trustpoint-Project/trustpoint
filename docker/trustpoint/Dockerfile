FROM python:3.14-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_FROZEN=1 \
    TRUSTPOINT_HSM_ROOT=/var/lib/trustpoint/hsm \
    SOFTHSM2_CONF=/var/lib/trustpoint/hsm/config/softhsm2.conf

# Make port 80 and 443 available outside this container.
# Port 80 will be redirected to 443 using TLS through NGINX.
EXPOSE 80 443

# Update apt repositories and install required runtime dependencies.
# This includes the SoftHSM module used by Trustpoint's local/dev HSM setup.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        opensc \
        sudo \
        apt-utils \
        nginx \
        nginx-dev \
        gettext \
        locales \
        git \
        build-essential \
        cmake \
        libssl-dev \
        libseccomp-dev \
        softhsm2 \
        libpkcs11-proxy0 \
        curl \
        ca-certificates \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

# Build against the source headers shipped with the installed Debian nginx.
# --with-compat preserves the packaged binary's dynamic-module ABI. Keep the
# load directive outside the site file so wizard site switches retain it.
COPY docker/trustpoint/nginx/tls-binding/ /tmp/trustpoint-tls-binding/
RUN cd /usr/share/nginx/src && \
    ./configure --with-compat --with-http_ssl_module \
        --add-dynamic-module=/tmp/trustpoint-tls-binding && \
    make -f objs/Makefile modules && \
    install -d -m 755 /usr/lib/nginx/modules /etc/nginx/modules-enabled && \
    install -m 644 objs/ngx_http_trustpoint_tls_binding_module.so /usr/lib/nginx/modules/ && \
    printf '%s\n' 'load_module /usr/lib/nginx/modules/ngx_http_trustpoint_tls_binding_module.so;' \
        > /etc/nginx/modules-enabled/50-trustpoint-tls-binding.conf && \
    printf '%s\n' 'include /etc/nginx/modules-enabled/*.conf;' \
        'error_log stderr;' 'events {}' 'http {}' \
        > /tmp/trustpoint-nginx-module-check.conf && \
    nginx -t -c /tmp/trustpoint-nginx-module-check.conf && \
    rm -rf /tmp/trustpoint-tls-binding /tmp/trustpoint-nginx-module-check.conf

# Create stable PKCS#11 module paths so provider-profile bootstrap and
# local/dev configuration can rely on predictable values.
RUN softhsm_lib="$(ldconfig -p | awk '/libsofthsm2\.so/ {print $NF; exit}')" && \
    if [ -z "${softhsm_lib}" ]; then softhsm_lib="/usr/lib/softhsm/libsofthsm2.so"; fi && \
    ln -sf "${softhsm_lib}" /usr/lib/libsofthsm2.so && \
    proxy_lib="$(ldconfig -p | awk '/libpkcs11-proxy\.so/ {print $NF; exit}')" && \
    if [ -n "${proxy_lib}" ]; then ln -sf "${proxy_lib}" /usr/lib/libpkcs11-proxy.so; fi

# Install PostgreSQL 18 client.
RUN curl -fSsL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.gpg] http://apt.postgresql.org/pub/repos/apt/ trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client-18 && \
    rm -rf /var/lib/apt/lists/*

# Set locale settings.
RUN sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

WORKDIR /var/www/html/trustpoint/

COPY --chown=www-data:www-data pyproject.toml uv.lock ./

# Build the checked-out revision; do not fetch another source tree inside the image.
RUN chmod 755 /var/www/html/trustpoint/ && \
    chown www-data:www-data /var/www/html/trustpoint/

USER www-data
# Install dependencies before copying application sources to leverage Docker caching.
RUN uv sync --no-install-project --no-dev --group docs --group docker --python-preference only-system

COPY --chown=www-data:www-data README.md LICENSE ./
COPY --chown=www-data:www-data THIRD_PARTY_LICENSES/ ./THIRD_PARTY_LICENSES/
COPY --chown=www-data:www-data trustpoint/ ./trustpoint/
COPY --chown=www-data:www-data docker/trustpoint/ ./docker/trustpoint/
# Keep the in-app documentation builder available without copying local builds.
COPY --chown=www-data:www-data docs/source/ ./docs/source/
COPY --chown=www-data:www-data docs/Makefile ./docs/
# Demo-data setup imports these public chains; do not copy fixture private-key bundles.
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/ecc1/ecc1_chain.pem ./tests/data/idevid_hierarchies/ecc1/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/ecc2/ecc2_chain.pem ./tests/data/idevid_hierarchies/ecc2/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/ecc3/ecc3_chain.pem ./tests/data/idevid_hierarchies/ecc3/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/rsa2/rsa2_chain.pem ./tests/data/idevid_hierarchies/rsa2/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/rsa3/rsa3_chain.pem ./tests/data/idevid_hierarchies/rsa3/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/rsa4/rsa4_chain.pem ./tests/data/idevid_hierarchies/rsa4/
COPY --chown=www-data:www-data tests/data/idevid_hierarchies/mldsa65/mldsa65_chain.pem ./tests/data/idevid_hierarchies/mldsa65/
RUN uv sync --no-dev --group docs --group docker --python-preference only-system
USER root

# Prepare Trustpoint runtime directories.
# For the local/dev setup, Trustpoint uses the SoftHSM PKCS#11 module directly
# against the mounted token directory.
RUN chown root:root /var/www/html/trustpoint /var/www/html/trustpoint/docker && \
    chown -R root:root /var/www/html/trustpoint/docker/trustpoint && \
    mkdir -p /var/www/html/trustpoint/trustpoint/media/log \
             /var/www/html/trustpoint/trustpoint/collected_static \
             /var/www/html/trustpoint/docker/trustpoint/nginx/tls \
             /var/lib/trustpoint/bootstrap \
             /var/lib/trustpoint/hsm/config && \
    chown -R www-data:www-data /var/lib/trustpoint/bootstrap && \
    chown -R www-data:www-data /var/lib/trustpoint/hsm && \
    chown -R www-data:www-data /var/www/html/trustpoint/docker/trustpoint/nginx/tls && \
    chmod -R 755 /var/www/html/trustpoint/trustpoint/ && \
    chmod 750 /var/lib/trustpoint/bootstrap && \
    chmod 750 /var/lib/trustpoint/hsm /var/lib/trustpoint/hsm/config && \
    chmod -R 755 /var/www/html/trustpoint/docker/trustpoint/nginx/tls

# Set DEBUG = False and DOCKER_CONTAINER = True in the Django settings.
RUN sed -i '/DEBUG = True/s/True/False/' trustpoint/trustpoint/settings.py && \
    sed -i '/DOCKER_CONTAINER = False/s/False/True/' trustpoint/trustpoint/settings.py

# Create and set up the /etc/trustpoint/ directory.
RUN mkdir -p /etc/trustpoint/ && \
    cp -r /var/www/html/trustpoint/docker/trustpoint/* /etc/trustpoint/ && \
    chown -R root:root /etc/trustpoint/ && \
    chmod -R 755 /etc/trustpoint/

# Add sudoers file and configure user and restart sudo service.
RUN cp ./docker/trustpoint/wizard/sudoers /etc/sudoers && \
    chown root:root /etc/sudoers && \
    chmod 440 /etc/sudoers && \
    visudo -cf /etc/sudoers && \
    service sudo restart

# The deployment supplies /run/secrets/django_secret_key as a read-only Compose secret.
# No signing key is generated or stored in this image.

# NGINX configuration.
RUN rm -f /etc/nginx/sites-enabled/*
COPY ./docker/trustpoint/nginx/trustpoint-nginx-https.conf /etc/nginx/sites-available/trustpoint

RUN chmod +x /etc/trustpoint/wizard/transition/*.sh \
             /etc/trustpoint/wizard/configure_nginx.sh \
             /etc/trustpoint/wizard/install_pkcs11_assets.sh \
             /etc/trustpoint/wizard/switch_to_operational.sh \
             /etc/trustpoint/wizard/update_tls.sh \
             /etc/trustpoint/wizard/update_tls_nginx.sh \
             /etc/trustpoint/wizard/wizard_restore.sh \
             ./docker/trustpoint/entrypoint.sh

# Translation catalogs are image artifacts; runtime startup must not write code.
RUN .venv/bin/python -m django compilemessages -l de -l en --ignore .venv

# Apply ownership last, after all installations and generated image artifacts.
RUN /bin/bash /etc/trustpoint/lock_application.sh

# The root entrypoint and its parser must never be loaded from web-writable code.
ENTRYPOINT ["/bin/bash", "/etc/trustpoint/entrypoint.sh"]
