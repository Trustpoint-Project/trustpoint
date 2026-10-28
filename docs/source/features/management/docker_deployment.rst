Docker Compose Deployment
============================

Docker Compose is the supported Docker deployment mechanism. The application web
setup wizard remains available for configuring Trustpoint after deployment.

Prerequisites
----------------

Use a Linux server with Docker Engine, Docker Compose v2.32.4 or newer, Git,
Python 3, and administrator access. The examples run Docker as an authorized
Docker user; prefix Docker commands with ``sudo`` if required on your server.
Set the database password, TLS DNS/IP names, and exposed ports in ``.env``.

Fresh Installation
---------------------

From a release checkout:

.. code-block:: bash

   cp .env.example .env
   chmod 600 .env
   # Edit .env before exposing the installation.
   sudo python3 docker/init_secret.py --type all
   docker compose up -d --build --wait --wait-timeout 300

Open ``https://<your-server>/``. Accept the initial certificate as appropriate and
complete the web setup wizard. Initial bootstrap login details are available in
``docker compose logs trustpoint``. The container handles database initialization,
migrations, and nginx/HTTPS configuration; no host deployment wizard is needed.

To use a published application image, set ``TRUSTPOINT_IMAGE`` to the desired
release image in ``.env``, then use ``docker compose pull`` and
``docker compose up -d --no-build --wait --wait-timeout 300`` instead.
Keep the Compose configuration from that release alongside the deployment. Use
a separate deployment directory or secret source file for each installation; only
that installation's web and workers should share its key.

Signing Key Initialization
-----------------------------

``docker/init_secret.py`` provisions host secret files. It does not run
Docker, rewrite ``.env``, or alter an existing deployment. Run it once with sudo:

.. code-block:: bash

   sudo python3 docker/init_secret.py

The default ``--type django`` creates only Django's signing key. For the software
backend, initialize the independent database KEK as well:

.. code-block:: bash

   sudo python3 docker/init_secret.py --type kek
   # Or initialize both in one invocation:
   sudo python3 docker/init_secret.py --type all

``--type kek`` creates ``secrets/trustpoint_software_kek`` using
``secrets.token_hex(32)``: exactly 64 hexadecimal characters, without a newline.
``--type all`` validates and preserves each existing secret independently. If the
second operation fails, the first result remains in place; resolve the error
and rerun. ``--path`` and the Django-only ``--import-from`` require a single type.

The Django default creates ``secrets/django_secret_key`` using cryptographically secure randomness
and atomic file creation. The file is owned by root, group 33 (the image's
``www-data`` group), with mode ``0440``. The invoking administrator owns the
private secrets directory, so Compose can locate its source file. Do not make the
file world-readable to resolve permission errors.

Repeating initialization leaves an existing valid key unchanged. Empty files,
symlinks, incorrect permissions, and conflicting imports cause an error instead
of replacement. The initializer never prints the key. ``secrets/`` is excluded
from Git and the Docker build context.

Compose binds the file read-only at ``/run/secrets/django_secret_key`` in every
Django service. File-based Compose secrets preserve host ownership; declaring
``uid`` or ``gid`` in Compose does not remap the host file. The initializer's
permissions therefore matter on Linux. See the `Compose secrets reference
<https://docs.docker.com/reference/compose-file/services/#secrets>`_.

``DJANGO_SECRET_KEY_HOST_FILE`` selects another host source file;
``DJANGO_SECRET_KEY_FILE`` selects its in-container target. For example, provision
an external deployment directory with ``--path /srv/trustpoint-secrets/django_secret_key``
and set the host-file variable to that path. The application reads the file
contents exactly, including trailing newlines, to preserve imported signatures.
Production fails clearly when the file is missing, empty, or unreadable. It
never generates a production key. Images contain no key.

The main and worker Compose files also mount the software KEK read-only at
``/run/secrets/trustpoint_software_kek``. Override its host source with
``TRUSTPOINT_SOFTWARE_KEK_HOST_FILE``. It is independent of Django signing and
required even for local software-backend development. See
:doc:`../security/db_encryption` for the Trustpoint 1.0 envelope format and recovery.
On macOS, Docker Desktop may map host numeric IDs differently; verify guest
``www-data`` read access. Linux production ownership stays root:33/0440. Do not
make the key world-readable to work around Desktop file sharing.

Local, non-Docker development uses a separate generated Django signing key in
ignored ``var/development/`` storage. With ``DEBUG=True`` and no explicit
``TRUSTPOINT_SOFTWARE_KEK_FILE``, fresh software-backend initialization also
creates ``var/development/software_kek`` atomically with mode ``0600``. It is
reused across local commands and server restarts. If it goes missing after
initialization, restore the original file; no replacement is generated. These
development defaults are unavailable in Docker and non-debug deployments.

Start, Stop, And Inspect
---------------------------

.. code-block:: bash

   docker compose up -d --wait --wait-timeout 300
   docker compose ps
   docker compose logs --tail 100 trustpoint
   docker compose stop

``docker compose down`` removes this project's containers and network but keeps
named volumes. ``docker compose down -v`` deletes persistent data; do not use it
for routine stops or upgrades. Preserve the project name and deployment files.
Use ``docker compose -p <project>`` consistently when choosing a custom name.

Optional Services
--------------------

Background worker
~~~~~~~~~~~~~~~~~~~~

The standalone worker configuration adds a workflows2 worker using the same
secret, bootstrap handoff, media, and HSM storage as the web service:

.. code-block:: bash

   docker compose -f docker-compose.worker.yml up -d --build --wait --wait-timeout 300

Keep using that Compose file for subsequent operations. Worker lease, batch,
sleep, and ID options remain configurable through ``WORKFLOWS2_WORKER_*`` in
``.env``.

SoftHSM
~~~~~~~~~~

SoftHSM is intended for local development and integration testing. For this
configuration, provision the existing file-based PostgreSQL credentials too:

.. code-block:: bash

   sudo python3 docker/init_secret.py
   # Run only when these database credential files do not already exist.
   (umask 077; set -C; printf '%s\n' admin > db_user.txt)
   (umask 077; set -C; openssl rand -hex 32 > db_password.txt)
   sudo chown root:33 db_user.txt db_password.txt
   sudo chmod 0440 db_user.txt db_password.txt
   docker compose -f docker-compose.softhsm.yml up -d --build --wait --wait-timeout 300

This standalone PKCS#11 configuration requires only Django's secret, not a
software KEK. Select the HSM app-secret backend in the web setup wizard.
Enable its optional worker with ``--profile worker``. The SoftHSM service owns
its token/config volumes. Trustpoint uses the direct SoftHSM PKCS#11 module and
shared token storage because application-secret protection requires mechanisms
that the proxy does not expose. The web setup wizard consumes the local provider
configuration; no host-side provider-upsert script is required. Local proxy test
tools can connect to localhost port 5657 (override ``SOFTHSM_PROXY_PORT`` if needed);
the unauthenticated test proxy is not published on external interfaces.

The active PIN files are ``user-pin.txt`` and ``so-pin.txt`` inside
``softhsm_config``. They are created only for a new token. An existing token with
missing PIN files stops with an error; restore its original PINs rather than
reinitializing or deleting the token. Keep hardware HSM keys and recovery material
according to the vendor's procedures.

External PKCS#11 provider
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For an external provider, configure the provider module, token selector, and PIN
file in the web setup wizard. Initialize Django's secret only and remove the
software KEK mount with the PKCS#11-only override:

.. code-block:: bash

   sudo python3 docker/init_secret.py
   docker compose -f docker-compose.yml -f docker-compose.pkcs11.yml up -d --build

For workers use all three files consistently:

.. code-block:: bash

   docker compose -f docker-compose.worker.yml -f docker-compose.pkcs11.yml \
     -f docker-compose.worker.pkcs11.yml up -d --build

The overrides use Compose's ``!override`` sequence replacement. No dummy software
KEK file is needed. Supply HSM PIN credentials through the existing file-based
provider configuration or a separate credential secret mount; never export raw
HSM KEKs. Preserve token state across updates.

Demo mail and SFTP
~~~~~~~~~~~~~~~~~~~~~

Export a separate ``SFTPGO_ADMIN_PASSWORD`` in the deployment shell and start
the optional helper configuration. Keep this helper-admin credential out of the
application's ``.env`` file:

.. code-block:: bash

   docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build

Mailpit's inbox is available on localhost port 8025; the application sends mail
to ``mailpit:1025``. SFTPGo's administration UI is on localhost port 8080 and SFTP
on localhost port 2222. Create a backup user and directory through the SFTPGo UI,
then configure Trustpoint's SFTP backup settings to use ``sftpgo:2022``. The old
interactive workflow's automatic SFTP user provisioning is replaced by this
manual configuration. When combining demo services with a separate worker, set
``EMAIL_HOST=mailpit``, ``EMAIL_PORT=1025``, ``EMAIL_USE_TLS=false``, and
``EMAIL_USE_SSL=false`` in ``.env`` so the worker uses the same SMTP server.
These helpers are optional test services, not a production
mail or backup architecture. Use SSH forwarding for remote access to their UIs.

mDNS and external PostgreSQL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Linux, add ``-f docker-compose.mdns.yml`` to advertise the service. The
advertiser uses host networking and additional capabilities; it remains separate
from the application container. Docker Desktop is not supported for mDNS.

For external PostgreSQL, set the existing ``DATABASE_*`` and ``POSTGRES_DB``
settings, then start only the application service with
``docker compose up -d --build --no-deps trustpoint``. Start any workers separately
after the web service is healthy. Keep database credentials consistent with the
web setup wizard. Configure HTTPS names and ports through ``TP_TLS_*``,
``TP_HTTP_PORT``, and ``TP_HTTPS_PORT`` in ``.env``.

Persistence And Backups
--------------------------

.. list-table:: Deployment state
   :header-rows: 1

   * - State
     - Storage
   * - Django signing key
     - Host file ``secrets/django_secret_key``, mounted read-only
   * - Software database KEK
     - Host file ``secrets/trustpoint_software_kek``, mounted read-only
   * - PostgreSQL database
     - ``postgres_data`` volume
   * - Bootstrap database and operational handoff
     - ``trustpoint_bootstrap`` volume
   * - Media, logs, and local backups
     - ``trustpoint_media`` volume
   * - Provider libraries/configuration and local crypto state
     - ``trustpoint_hsm`` volume
   * - SoftHSM token/configuration when enabled
     - ``softhsm_tokens`` and ``softhsm_config`` volumes

Back up the database, signing-key file, software KEK, ``.env``, other credential files, and all
applicable runtime volumes. Pause application/worker and other writers when taking
a coordinated filesystem snapshot. Hardware HSM backups are separate. See
:doc:`backups` and :doc:`../../development/architecture/backup_restore`.

For an existing Trustpoint 1.0 deployment, before first recreating a container with new volume mounts,
explicitly copy its bootstrap, media, and HSM state into the corresponding
volumes. An empty volume does not recover files from a previous container's
writable layer. Do not discard that container until recovery copies exist.

Routine Updates
------------------

Follow :doc:`upgrading` for the upgrade procedure, including database and key
backups, source-built or published images, worker ordering, validation, and
rollback. Keep the same Compose project, configuration, secret files, and runtime
volumes. Rebuilding an image alone does not migrate an unsupported database.

Pre-1.0 Installations
------------------------

Migration of encrypted databases from pre-1.0 releases is unsupported. Deploy
Trustpoint 1.0 with a fresh database and independent secrets. Keep the original
installation and its backups intact until a separately supported migration path
is available. The application schema transition refuses existing pre-1.0 key
material instead of silently deleting or converting it.

The initializer still supports explicit Django signing-key import with
``--import-from``; importing that key does not migrate encrypted fields or HSM
state. Do not fake migrations or point a fresh installation at old encrypted data.

Rotation, Recovery, And Troubleshooting
------------------------------------------

A key is installation-specific and shared by all Django services. Rotate it only
as a planned administrator action: retain a private copy, provision the replacement
in a new file, point ``DJANGO_SECRET_KEY_HOST_FILE`` to it, and recreate all Django
services using ``--force-recreate``. Changing a file alone does not refresh the
key already loaded by running Django processes. Without a configured fallback
key, old signatures, password-reset links,
and authenticated sessions become invalid. Rotation does not change user password
hashes or the separate database-encryption/HSM keys. Django's
``SECRET_KEY_FALLBACKS`` can support a separately planned grace-period deployment;
this configuration does not automatically retain previous keys.

* Missing file: run the one-time initializer, or restore/import the original key
  for an existing installation. Check ``DJANGO_SECRET_KEY_HOST_FILE``.
* Unreadable file: check host ownership and numeric group 33 with ``sudo stat``.
  The application requires group read permission, mode ``0440``. The initializer
  reports incorrect existing permissions without modifying them. The file's
  parent must be traversable by the host user invoking Compose.
* Empty file: restore the correct key; an existing empty file is not replaced.
* Unexpected logout after an update: verify that the exact old key was preserved
  and that every application service mounts the same source file.
* Existing key generated in a previous secrets volume: explicitly copy its
  ``django_secret_key.env`` file out of that volume and use ``--import-from``.
* Changed or lost HSM PIN: restore the original PIN and matching token storage;
  changing a host PIN file does not change the token's PIN.

If the signing key is lost and no backup exists, its signatures cannot be
recovered. Generating another key is a deliberate recovery action, not a normal
startup behavior.

Software KEKs must remain unchanged for the lifetime of the current encrypted
database. A replacement KEK cannot decrypt its wrapped DEK. Software KEK and DEK
rotation are not implemented. Missing, invalid, or wrong KEKs cause cryptographic
operations to fail without generating a new DEK. Restore the original KEK and
matching database backup; see :doc:`../security/db_encryption`.
