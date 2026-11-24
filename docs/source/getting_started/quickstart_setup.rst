.. _quickstart-setup-guide:

Quickstart Setup
================

Deploy Trustpoint with Docker Compose or Podman on a Linux server. You need
Docker Engine and Docker Compose v2.32.4 or newer, or Podman 5 or newer with
the Docker Compose provider, plus Git, Python 3, and administrator access. Podman
deployments on Linux use ``podman compose`` and initialize secrets with
``podman unshare python3 docker/init_secret.py --type all`` instead of ``sudo``.
Enable the user socket with ``systemctl --user enable --now podman.socket`` and
set ``TP_HTTP_PORT=8080`` and ``TP_HTTPS_PORT=8443`` in ``.env`` before starting.
See :doc:`../features/management/docker_deployment` for the rootless instructions;
the commands below show Docker deployment.

Run the Podman commands on the Linux host; ``podman unshare`` is unavailable
in the macOS/Windows remote client.

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
runtime state before container replacement. Trustpoint 1.0.0 is the first stable
version and the baseline for subsequent updates.

See :doc:`../features/management/docker_deployment` for published images, workers,
SoftHSM, demo mail/SFTP services, external PostgreSQL, upgrades, and secret recovery. Continue with
:ref:`quickstart-operation-guide` after setup.
