# Build the nginx dynamic module in a throw-away stage so the runtime image
# does not need a compiler, cmake, git, or nginx headers.
FROM python:3.14-slim-trixie AS nginx-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libssl-dev \
        nginx-dev && \
    rm -rf /var/lib/apt/lists/*

COPY docker/trustpoint/nginx/tls-binding/ /tmp/trustpoint-tls-binding/
RUN cd /usr/share/nginx/src && \
    ./configure --with-compat --with-http_ssl_module \
        --add-dynamic-module=/tmp/trustpoint-tls-binding && \
    make -f objs/Makefile modules && \
    install -d -m 755 /out/modules /out/modules-enabled && \
    install -m 644 objs/ngx_http_trustpoint_tls_binding_module.so /out/modules/ && \
    printf '%s\n' 'load_module /usr/lib/nginx/modules/ngx_http_trustpoint_tls_binding_module.so;' \
        > /out/modules-enabled/50-trustpoint-tls-binding.conf && \
    printf '%s\n' 'load_module /out/modules/ngx_http_trustpoint_tls_binding_module.so;' \
        'error_log stderr;' 'events {}' 'http {}' \
        > /tmp/trustpoint-nginx-module-check.conf && \
    nginx -t -c /tmp/trustpoint-nginx-module-check.conf && \
    rm -rf /tmp/trustpoint-tls-binding /tmp/trustpoint-nginx-module-check.conf

FROM python:3.14-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /uvx /bin/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    UV_FROZEN=1 \
    TRUSTPOINT_CONTAINER=1 \
    TRUSTPOINT_HSM_ROOT=/var/lib/trustpoint/hsm \
    SOFTHSM2_CONF=/var/lib/trustpoint/hsm/config/softhsm2.conf

# Make port 80 and 443 available outside this container.
# Port 80 will be redirected to 443 using TLS through NGINX.
EXPOSE 80 443

# Runtime packages only. The nginx module is built in the stage above.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        opensc \
        nginx \
        gettext \
        locales \
        softhsm2 \
        libpkcs11-proxy0 \
        curl \
        ca-certificates \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

COPY --from=nginx-builder /out/modules/ngx_http_trustpoint_tls_binding_module.so /usr/lib/nginx/modules/
COPY --from=nginx-builder /out/modules-enabled/50-trustpoint-tls-binding.conf /etc/nginx/modules-enabled/

# Fail the build here if the runtime nginx cannot load the compiled module.
# Avoid Debian's default port-80 listener in rootless builds using the host network.
RUN printf '%s\n' 'include /etc/nginx/modules-enabled/*.conf;' \
        'error_log stderr;' 'events {}' 'http {}' \
        > /tmp/trustpoint-nginx-module-check.conf && \
    nginx -t -c /tmp/trustpoint-nginx-module-check.conf && \
    rm /tmp/trustpoint-nginx-module-check.conf

# Create stable PKCS#11 module paths so provider-profile bootstrap and
# local/dev configuration can rely on predictable values.
RUN softhsm_lib="$(ldconfig -p | awk '/libsofthsm2\.so/ {print $NF; exit}')" && \
    if [ -z "${softhsm_lib}" ]; then softhsm_lib="/usr/lib/softhsm/libsofthsm2.so"; fi && \
    ln -sf "${softhsm_lib}" /usr/lib/libsofthsm2.so && \
    proxy_lib="$(ldconfig -p | awk '/libpkcs11-proxy\.so/ {print $NF; exit}')" && \
    if [ -n "${proxy_lib}" ]; then ln -sf "${proxy_lib}" /usr/lib/libpkcs11-proxy.so; fi

# Install PostgreSQL 18 client.
RUN curl -fSsL --retry 5 --retry-all-errors --connect-timeout 10 --max-time 60 \
        https://apt.postgresql.org/pub/repos/apt/ACCC4CF8.asc \
        -o /usr/share/keyrings/postgresql-archive-keyring.asc && \
    echo "deb [signed-by=/usr/share/keyrings/postgresql-archive-keyring.asc] https://apt.postgresql.org/pub/repos/apt/ trixie-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get -o Acquire::Retries=3 update && \
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends postgresql-client-18 && \
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
RUN rm -f /bin/uv /bin/uvx

# Prepare Trustpoint runtime directories.
# The HSM root stays root-owned so a web-account compromise cannot turn the
# fixed PKCS#11 install paths into symlinks. The app reads the 0640 group files.
RUN chown root:root /var/www/html/trustpoint /var/www/html/trustpoint/docker && \
    chown -R root:root /var/www/html/trustpoint/docker/trustpoint && \
    mkdir -p /var/www/html/trustpoint/trustpoint/media/log \
             /var/www/html/trustpoint/trustpoint/collected_static \
             /var/www/html/trustpoint/docker/trustpoint/nginx/tls \
             /var/lib/trustpoint/bootstrap \
             /var/lib/trustpoint/hsm/config \
             /var/lib/trustpoint/hsm/lib && \
    chown -R www-data:www-data /var/lib/trustpoint/bootstrap && \
    chown root:root /var/lib/trustpoint/hsm && \
    chown -R root:www-data /var/lib/trustpoint/hsm/config /var/lib/trustpoint/hsm/lib && \
    chown -R www-data:www-data /var/www/html/trustpoint/docker/trustpoint/nginx/tls && \
    chmod -R 755 /var/www/html/trustpoint/trustpoint/ && \
    chmod 750 /var/lib/trustpoint/bootstrap && \
    chmod 755 /var/lib/trustpoint/hsm && \
    chmod 750 /var/lib/trustpoint/hsm/config /var/lib/trustpoint/hsm/lib && \
    chmod -R 755 /var/www/html/trustpoint/docker/trustpoint/nginx/tls

# Create and set up the /etc/trustpoint/ directory.
RUN mkdir -p /etc/trustpoint/ && \
    cp -r /var/www/html/trustpoint/docker/trustpoint/* /etc/trustpoint/ && \
    chown -R root:root /etc/trustpoint/ && \
    chmod -R 755 /etc/trustpoint/ && \
    rm -rf /var/www/html/trustpoint/docker/trustpoint/nginx/tls-binding && \
    rm -f /etc/trustpoint/nginx/tls-binding/ngx_http_trustpoint_tls_binding_module.c \
          /etc/trustpoint/nginx/tls-binding/config

# The deployment supplies /run/secrets/django_secret_key as a read-only Compose secret.
# No signing key is generated or stored in this image.

# NGINX configuration.
RUN rm -f /etc/nginx/sites-enabled/*
COPY ./docker/trustpoint/nginx/trustpoint-nginx-https.conf /etc/nginx/sites-available/trustpoint

RUN chmod +x /etc/trustpoint/wizard/configure_nginx.sh \
             /etc/trustpoint/wizard/install_pkcs11_assets.sh \
             /etc/trustpoint/wizard/switch_to_operational.sh \
             /etc/trustpoint/wizard/update_tls.sh \
             /etc/trustpoint/wizard/update_tls_nginx.sh \
             ./docker/trustpoint/entrypoint.sh

# Translation catalogs are image artifacts; runtime startup must not write code.
RUN .venv/bin/python -m django compilemessages -l de -l en --ignore .venv

# Apply ownership last, after all installations and generated image artifacts.
RUN /bin/bash /etc/trustpoint/lock_application.sh

# The root entrypoint and its parser must never be loaded from web-writable code.
ENTRYPOINT ["/bin/bash", "/etc/trustpoint/entrypoint.sh"]
