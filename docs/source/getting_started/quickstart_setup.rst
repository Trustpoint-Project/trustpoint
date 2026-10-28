.. _quickstart-setup-guide:

Quickstart Setup
================

Deploy Trustpoint with Docker Compose on a Linux server. You need Docker Engine,
Docker Compose v2.32.4 or newer, Git, Python 3, and administrator access.

.. code-block:: bash

   git clone https://github.com/Trustpoint-Project/trustpoint.git
   cd trustpoint
   cp .env.example .env
   chmod 600 .env
   # Set a strong database password and the server's TLS names/IP addresses.
   sudo python3 docker/init_secret.py --type all
   docker compose up -d --build --wait --wait-timeout 300

The one-time initializer creates an installation-specific Django signing key and an independent software
database KEK on the host. It never replaces an existing key. Compose mounts both read-only in all
Django containers. Keep both keys, ``.env``, and named volumes for future updates.

Open ``https://<your-server>/`` and complete the web setup wizard. Obtain the
initial bootstrap credentials from ``docker compose logs trustpoint``. Startup
handles database initialization, migrations, and HTTPS configuration.

For automated setup, set these values in ``.env`` before starting:

.. code-block:: text

   TP_AUTO_SETUP=true
   TP_ADMIN_USERNAME=admin
   TP_ADMIN_PASSWORD=<a-strong-password>
   TP_INJECT_DEMO_DATA=false

Configure ``TP_TLS_DNS_NAMES``, ``TP_TLS_IPV4_ADDRESSES``, and
``TP_TLS_IPV6_ADDRESSES`` for the server. These values also configure allowed hosts
and trusted origins. ``TP_HTTP_PORT`` and ``TP_HTTPS_PORT`` select published ports.

.. code-block:: bash

   docker compose ps
   docker compose logs --tail 100 trustpoint
   docker compose stop

Stop with ``stop`` or ``down`` to keep persistent data. Do not use ``down -v`` for
routine maintenance. Existing 1.0 installations must preserve both keys and all
runtime state before container replacement. Pre-1.0 encrypted database migration
is unsupported.

See :doc:`../features/management/docker_deployment` for published images, workers,
SoftHSM, demo mail/SFTP services, external PostgreSQL, upgrades, and secret recovery. Continue with
:ref:`quickstart-operation-guide` after setup.
