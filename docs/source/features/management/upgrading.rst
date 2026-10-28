Upgrading Trustpoint
====================

Use this procedure to update an existing Docker Compose deployment while keeping
its database, cryptographic keys, configuration, and runtime storage. Plan a
maintenance window: enrollment endpoints and the web interface are unavailable
while the application is stopped.

Supported Upgrade Paths
-----------------------

Read the target release's release notes before changing the deployment. Upgrade
only when that release explicitly supports the installed database schema and
key-protection format. These instructions describe the mechanics of an upgrade;
they do not establish compatibility between arbitrary releases.

Migration of encrypted databases from pre-1.0 releases to the 1.0 envelope-encryption
architecture is unsupported. A fresh installation uses a fresh database; retaining
old volumes or importing Django's signing key does not convert encrypted data.
Keep the old installation and its recovery material until a supported migration
path exists.

Keep The Deployment Identity And State
--------------------------------------

Run commands from the existing deployment directory. Keep the same Compose project
name, ``.env``, Compose file selection, overrides, and enabled profiles. Changing
the project name can select new, empty named volumes.

Examples below use ``docker compose`` for the main deployment. If your installation
uses another configuration, include the same options before every command:

.. list-table:: Compose selection
   :header-rows: 1
   :widths: 30 70

   * - Deployment
     - Command prefix
   * - Standard
     - ``docker compose``
   * - Background worker
     - ``docker compose -f docker-compose.worker.yml``
   * - SoftHSM and worker
     - ``docker compose -f docker-compose.softhsm.yml --profile worker``
   * - External PKCS#11
     - ``docker compose -f docker-compose.yml -f docker-compose.pkcs11.yml``
   * - External PKCS#11 with worker
     - ``docker compose -f docker-compose.worker.yml -f docker-compose.pkcs11.yml -f docker-compose.worker.pkcs11.yml``

Also retain any existing ``-p <project-name>`` and additional overrides, including
mDNS or demo services. Do not replace your customized ``.env`` with ``.env.example``.

Preserve all of the following state:

.. list-table:: Required recovery material
   :header-rows: 1
   :widths: 35 65

   * - State
     - Why it is needed
   * - ``postgres_data`` or the external PostgreSQL database
     - Application data, migration history, and the wrapped DEK
   * - ``trustpoint_bootstrap``
     - Bootstrap database and the operational handoff configuration
   * - ``trustpoint_media``
     - Uploaded files, local backups, and logs
   * - ``trustpoint_hsm`` and custom provider mounts
     - Provider libraries, configuration, and other local crypto state
   * - Django signing-key host file
     - Existing signatures and authenticated sessions
   * - Software KEK host file, for software deployments
     - Recovery of the existing database's wrapped DEK
   * - HSM KEK/token and original credentials, for PKCS#11 deployments
     - Recovery of the wrapped DEK and access to managed keys
   * - ``softhsm_config`` and ``softhsm_tokens``, when enabled
     - SoftHSM configuration, original PIN files, and token objects

Keeping ``trustpoint_bootstrap`` alone is insufficient. The database and its
matching software KEK or HSM KEK must also survive. The default host secret files
are ``secrets/django_secret_key`` and ``secrets/trustpoint_software_kek``; use your
actual configured sources if different.

Do not run ``docker compose down -v`` or volume-pruning
commands during an upgrade. Do not regenerate secrets, reset the database,
reinitialize HSM tokens, or change encryption backends as part of this procedure.

1. Record The Current Deployment
--------------------------------

Check that the existing deployment is healthy and record its release, image IDs,
Compose options, and actual volume names in your maintenance record:

.. code-block:: bash

   docker compose ps
   docker compose images
   docker compose config --quiet
   git rev-parse HEAD

The Git command applies to a source checkout. Give the running application image
a separate local tag before building or pulling a replacement:

.. code-block:: bash

   rollback_image="trustpoint-local:pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
   docker image tag "$(docker compose images -q trustpoint)" "$rollback_image"
   printf 'Rollback image: %s\n' "$rollback_image"

Keep that image tag and the old deployment configuration available for rollback. Store configuration records
privately; full environment or container inspection output can contain credentials.

2. Create And Download A Backup Through Trustpoint
--------------------------------------------------

.. important::

   A new database backup created through the Trustpoint web interface is required
   before every upgrade. Download it outside the running Trustpoint instance.
   Do not continue if creation or download fails. A backup kept only in the
   container or its local backup volume does not satisfy this prerequisite.

Pause enrollment clients, automated configuration changes, scheduled jobs, and
other administrator writes for the maintenance window. If a separate worker is
running, stop it first using the deployment's Compose prefix:

.. code-block:: bash

   docker compose -f docker-compose.worker.yml stop trustpoint-worker

Keep the web application running while creating the backup:

1. Sign in to Trustpoint with permission to manage backups.
2. Open **Management > Backups**.
3. Click **Create Local Backup** and wait for successful completion.
4. Find the newly created backup in **Local Backups** and click its **Download**
   action. Selected backups can also be downloaded through **Download Selected
   (zip)** or **Download Selected (tar.gz)**.
5. Save the downloaded archive in a protected recovery location outside the
   Trustpoint container, preferably outside the Docker host. Check that the
   archive opens and contains the nonempty database payload and its matching
   ``<backup>.manifest.json`` sidecar. For selected downloads, inspect the
   individual backup bundle inside the outer archive. Retain both files together.
6. Record the backup filename, completion time, and installed Trustpoint release
   with your maintenance records.

Use the backup created for this maintenance window, rather than an older backup
already listed in the table. Keep writers paused until the upgrade is complete;
changes made after the backup are not included in the recovery point.

See :doc:`backups` for the web interface and
:doc:`../../development/architecture/backup_restore` for the payload/manifest
restore contract. The backup contains database data; the signing key, external
software KEK, HSM token, and runtime files need separate preservation below.

3. Stop The Application And Preserve Runtime State
--------------------------------------------------

After downloading the database backup, stop the web application:

.. code-block:: bash

   docker compose stop trustpoint

The separate worker must remain stopped. For SoftHSM, also stop the SoftHSM service
and any external token clients before archiving token files. Use the same Compose
prefix and project name for every command.

Create a private directory and archive the stopped application's persistent paths,
retaining tar metadata:

.. code-block:: bash

   umask 077
   backup_dir="$PWD/var/upgrade-backups/$(date -u +%Y%m%dT%H%M%SZ)"
   mkdir -p "$backup_dir"
   container_id=$(docker compose ps --all --quiet trustpoint)
   docker cp "$container_id:/var/lib/trustpoint/bootstrap" - > "$backup_dir/bootstrap.tar"
   docker cp "$container_id:/var/www/html/trustpoint/trustpoint/media" - > "$backup_dir/media.tar"
   docker cp "$container_id:/var/lib/trustpoint/hsm" - > "$backup_dir/hsm.tar"

Verify that these archives contain your mounted state. For SoftHSM, the HSM
archive must include the mounted ``config`` and ``tokens`` directories; separately
back up any provider state mounted elsewhere. Preserve numeric ownership and
permissions when restoring. Files left only in a container's writable layer must
be copied out before that container is replaced.

Separately back up ``.env``, Compose files, custom configuration, the exact signing
key, and the exact software KEK when used. Use privileged backup tooling to read
root-owned secret files without relaxing their permissions. Keep encrypted recovery
copies outside the Docker host and verify a restore in an isolated environment.
Opening an archive alone is not a complete restore test. Hardware HSM keys need
the vendor's supported backup procedure; a database dump cannot recover them.

4. Obtain The Target Application
--------------------------------

Choose one of the following methods. Review configuration changes required by the
target release and merge them into the existing deployment. Preserve all existing
secret paths and mounts.

Build from a release checkout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Check out the intended release without discarding local configuration changes,
then build only the application service:

.. code-block:: bash

   git fetch --tags
   # Review git status; replace YOUR_TARGET_RELEASE_TAG with the supported tag.
   git checkout YOUR_TARGET_RELEASE_TAG
   docker compose config --quiet
   docker compose build trustpoint

With a separate worker, build both ``trustpoint`` and ``trustpoint-worker`` using
the same target revision. They must use compatible code and the same secret files.

Use a published image
~~~~~~~~~~~~~~~~~~~~~

Set ``TRUSTPOINT_IMAGE`` in the existing ``.env`` to the target release's published
image tag or digest. Prefer a specific release or digest for reproducibility.
Then pull only the application:

.. code-block:: bash

   docker compose config --quiet
   docker compose pull trustpoint

If present, also pull ``trustpoint-worker`` with the same image selection. Keep
the previous image available; pulling or rebuilding a mutable tag can replace
its local tag association.

5. Recreate The Application And Validate
----------------------------------------

Keep PostgreSQL and the HSM on their current versions. If you stopped SoftHSM for
its backup, start the existing sidecar and wait for it to be healthy first.
Then recreate only the application:

.. code-block:: bash

   docker compose up -d --no-deps --no-build --force-recreate \
     --wait --wait-timeout 300 trustpoint
   docker compose ps
   docker compose logs --tail 100 trustpoint

The existing operational handoff selects the operational database. Application
startup applies pending Django migrations and checks access to the persisted DEK.
A wrong/missing KEK or damaged wrapped DEK must stop cryptographic operations;
never resolve that failure by generating replacement key material.

With a worker, start and validate the web service first, then recreate the worker
with the same release:

.. code-block:: bash

   docker compose -f docker-compose.worker.yml up -d --no-deps --no-build \
     --force-recreate --wait --wait-timeout 300 trustpoint-worker

Validate login, reading an existing encrypted credential, CA signing or certificate
enrollment, and workflow processing when enabled. Confirm the original CA identities,
TLS configuration, and backup settings remain available. Create and download a
new backup through **Management > Backups** before ending the maintenance window. A healthy HTTP endpoint alone does
not verify enrollment or all HSM operations.

The procedure recreates application containers with their existing mounts. Docker
explains this behavior in the `Compose up reference
<https://docs.docker.com/reference/cli/docker/compose/up/>`_. A PostgreSQL or HSM
software upgrade is a separate operation: do not attach an old PostgreSQL data
directory to a different major version without a supported database upgrade plan.

Rollback And Failed Upgrades
----------------------------

If startup or validation fails, keep the application and worker stopped while
investigating. Preserve the failure logs and the pre-upgrade backups.

Returning to the old image alone is safe only if its schema and runtime-state
compatibility is established. If the new release changed the database or provider
state, restore the matching pre-upgrade database and runtime backups using your
tested recovery procedure, then start the old release with its original Compose
configuration and keys. Do not restore an old dump over a live application or
merge incompatible HSM token snapshots. Changes made after the backup may be lost.

Missing migration columns usually indicate an incompatible schema or migration
history, rather than a missing image rebuild. Missing keys require recovery of the
original key material. Retrying with new secrets cannot recover encrypted data.

Local Development
-----------------

Create and download the database backup through the web interface as described
above before stopping development servers and workers. Preserve
``var/development/django_secret_key``
and ``var/development/software_kek`` or the explicitly configured key files.
Then update the checkout, run ``uv sync --locked``, apply migrations with
``uv run trustpoint/manage.py migrate``, and restart the development processes.

The local KEK helper creates a key only for a fresh backend; it will not recover
a lost key for an initialized database. ``reset_db`` and migration-file regeneration
are development reset operations, not upgrade procedures.
