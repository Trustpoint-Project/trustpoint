.. _trustpoint_dev_env_setup:

========================================
Trustpoint Development Environment Setup
========================================

Run the commands on this page from the repository root unless a command explicitly
changes directory. Native development uses Django's development server; production
uses the Linux Docker Compose deployment described in
:doc:`../features/management/docker_deployment`.

Python and dependencies
=======================

``pyproject.toml`` requires Python 3.13 or newer. The current Docker image and the
shared CI setup action use Python 3.14; use that interpreter when reproducing
release behavior. The checked-in ``uv.lock`` selects dependency versions.

Install uv, then create or synchronize the project environment:

.. code-block:: bash

   python3 -m pip install uv
   uv sync --locked --python 3.14

If you already use another environment, deactivate it before synchronizing this
project. ``uv run`` selects the project's environment without manual activation.
Do not delete an existing environment or change dependency versions just to run a
check. To use another supported interpreter, select it explicitly and record that
choice in test results.

Local database and application setup
====================================

Normal non-Docker development defaults to SQLite at ``trustpoint/db.sqlite3``.
PostgreSQL is selected explicitly; there is no automatic fallback from an
unavailable PostgreSQL server to SQLite. Production Docker deployments use
PostgreSQL.

For a fresh local SQLite database:

.. code-block:: bash

   export TRUSTPOINT_OPERATIONAL_DATABASE=sqlite
   uv run trustpoint/manage.py migrate
   uv run trustpoint/manage.py create_organization
   uv run trustpoint/manage.py create_builtin_groups
   uv run trustpoint/manage.py create_default_cert_profiles
   uv run trustpoint/manage.py create_default_agent_profile_definitions
   uv run trustpoint/manage.py seed_discovery_ports
   uv run trustpoint/manage.py sync_security_config
   uv run trustpoint/manage.py createsuperuser

Choose your own superuser credentials when prompted. To use a different local
SQLite file, set ``TRUSTPOINT_OPERATIONAL_SQLITE_PATH`` before running commands.
Never point local development or destructive test commands at a production database.

Local development KEK
---------------------

With the default debug-only SQLite settings, no manual KEK provisioning is
required before using ``runserver``. The software backend creates
``var/development/software_kek`` when it is first initialized during development
use, then reuses that file. Initialization is lazy: starting ``runserver`` alone
does not guarantee that a crypto backend has already been requested. Other
management commands that use the backend can also trigger first initialization.
Django's separate signing key is stored under ``var/development/`` as well.

If ``TRUSTPOINT_SOFTWARE_KEK_FILE`` is set, that file takes precedence and must
already exist; the application does not generate it. An initialized database
never receives a replacement KEK when its original file is missing. Preserve the
original keys with any database you want to reuse.

Docker secret provisioning
--------------------------

Docker and non-debug deployments do not use automatic development-key creation.
Use the existing host-side initializer before starting Compose:

.. code-block:: bash

   sudo python3 docker/init_secret.py --type all

This provisions ``secrets/django_secret_key`` and
``secrets/trustpoint_software_kek`` for the software-backed Compose deployment.
``--type kek`` provisions only the software KEK; ``--type django`` (the default)
provisions only Django's signing key. PKCS#11-only deployments need the Django
key and their configured HSM recovery material, rather than a software KEK.
The helper preserves valid existing files and rejects invalid contents,
permissions, or conflicting material instead of overwriting them. Its default
ownership/mode is root:33/0440 for the container's ``www-data`` group. See
:doc:`../features/management/docker_deployment` for mounts and recovery details.

PostgreSQL development
----------------------

For PostgreSQL development, create a separate database and role first, then set
``TRUSTPOINT_OPERATIONAL_DATABASE=postgresql``, ``POSTGRES_DB``, ``DATABASE_USER``,
``DATABASE_PASSWORD`` (or ``DATABASE_PASSWORD_FILE``), ``DATABASE_HOST``, and
``DATABASE_PORT``. Use an independent software KEK or a configured PKCS#11 provider.
For a disposable native test database only, setting
``TRUSTPOINT_AUTO_CONFIGURE_LOCAL_SOFTWARE_BACKEND=true`` permits local software
backend initialization. Do not carry that setting into a production environment.
See :doc:`../features/management/environment_configuration` for deployment settings.

Development server and background work
======================================

.. code-block:: bash

   uv run trustpoint/manage.py runserver 127.0.0.1:8000

Open ``http://127.0.0.1:8000/users/login/`` and use the superuser credentials you
created. For development HTTPS, use an unprivileged port and the public test
fixture credentials:

.. code-block:: bash

   uv run trustpoint/manage.py runserver_plus 127.0.0.1:8443 \
     --cert-file tests/data/x509/https_server.crt \
     --key-file tests/data/x509/https_server.pem

These committed keys and certificates are public test fixtures, never production
identities. ``runserver_plus`` also prepares the active development TLS credential
and starts Django-Q2. ``runserver_with_qcluster`` provides an HTTP server with that
worker. Both accept ``--no-qcluster`` when you run a separate worker:

.. code-block:: bash

   # In another terminal, with the same database and KEK configuration:
   uv run trustpoint/manage.py qcluster

The worker is not restarted automatically when server code reloads. Workflow
execution has its own inline/worker configuration; see
:doc:`../features/workflows/index`.

Tests and test secrets
======================

Application pytest tests live under ``trustpoint/``; root utility tests live under
``tests/``. Include both directories. Behave capability scenarios live under
``trustpoint/features/`` and run through Django's management command.

For an explicit reusable test KEK, use ``docker/init_secret.py`` rather than a
separate key-generation script. The example below selects an independent test
file and makes it readable by your native user's group instead of container group
33. It requires sudo to create the root-owned file:

.. code-block:: bash

   export TRUSTPOINT_OPERATIONAL_DATABASE=sqlite
   export TRUSTPOINT_SOFTWARE_KEK_FILE="$PWD/var/development/test-software-kek"
   sudo python3 docker/init_secret.py --type kek \
     --path "$TRUSTPOINT_SOFTWARE_KEK_FILE" --group-id "$(id -g)"

This explicit setup is separate from ``runserver``'s automatic development
initialization. Keep the same file for commands that share encrypted test data;
do not select a deployment's real KEK. An existing file with different ownership
or permissions is rejected, not silently repaired.

Run both suites from the same shell so they receive that configuration:

.. code-block:: bash

   uv run pytest trustpoint/ tests/
   uv run trustpoint/manage.py behave trustpoint/features/

Django test runners create separate test databases; PostgreSQL test roles need
permission to create them. Do not disable test-database isolation. Tests that
start local HTTP, CMP, or OPC UA servers require loopback socket access. On macOS,
use the native temporary directory if ``/tmp`` inherits a group that differs from
your process group; the secret-initializer tests check ownership as well as content.
Some root URL-validation tests currently depend on external DNS, so record resolver
failures rather than treating them as a clean test pass.

SQLite cannot test PostgreSQL row locks. Run the concurrency suite against an
isolated PostgreSQL database as part of release validation. Real PKCS#11 tests need
a configured reachable provider; real GDS workflow tests require
``RUN_GDS_INTEGRATION=1`` and their local server prerequisites. Inspect skipped-test
reasons rather than counting them as passes. Deployment and key-persistence
regressions are documented in :doc:`release-checklist`.

Quality checks and migrations
=============================

Use the versions locked by the project environment (currently Ruff 0.17.3 and mypy
2.4.0), rather than assuming older pre-commit hook versions reproduce CI:

.. code-block:: bash

   uv run ruff check .
   uv run ruff format --check .
   uv run mypy .
   uv run trustpoint/manage.py check
   uv run trustpoint/manage.py makemigrations --check --dry-run

``ruff format .`` applies formatting when you intend to edit files. The current
repository has formatting differences; do not silently treat a failed formatter
check as success. Pre-commit tool pins currently differ from the project versions.

After intentional model changes, create and inspect migrations:

.. code-block:: bash

   uv run trustpoint/manage.py makemigrations
   uv run trustpoint/manage.py migrate

Keep published migration history. Multiple migrations can be necessary to resolve
cross-app dependencies; do not merge or delete them merely because numbers or
version suffixes resemble each other. Test fresh installation and every supported
forward-upgrade path separately.

``reset_db`` is a destructive development helper for a throwaway database. It
preserves existing migration files by default, to recreate the current schema. ``--keep-all-migrations`` remains accepted for
existing scripts. Only the explicit ``--initial-migrations`` option deletes and
regenerates migration history; do not use it for the stable release baseline.
Without ``--no-user`` the reset creates ``admin`` / ``testing321``. It is not a
normal installation, upgrade, or release verification command.

Optional demo and protocol fixtures
====================================

The following management commands prepare data for local development:

.. list-table:: Development data commands
   :header-rows: 1
   :widths: 35 65

   * - Command
     - Purpose
   * - ``add_domains_and_devices``
     - Populate demo domains and devices, create test issuing CAs when needed,
       and import IDevID truststores.
   * - ``create_protocol_test_env``
     - Prepare enrollment-protocol fixtures and export their connection details
       and synthetic credentials as JSON.

After local setup, populate a disposable development instance with demo data:

.. code-block:: bash

   uv run trustpoint/manage.py add_domains_and_devices

Use a disposable development instance, never one holding real devices or keys.
To prepare protocol endpoint fixtures and exercise a running local HTTPS server:

.. code-block:: bash

   uv run trustpoint/manage.py create_protocol_test_env --output var/protocol_test_env.json
   bash tests/scripts/test_protocol_endpoints.sh \
     --host 127.0.0.1:8443 \
     --env-file var/protocol_test_env.json \
     --tls-cert tests/data/x509/https_server.crt

The CMP ML-DSA case needs OpenSSL 3.5 or newer. Generated protocol configuration
contains synthetic enrollment credentials; keep it private and outside Git.
For complete RA fixture setup, follow the enrollment-endpoints workflow included
in :doc:`testing/ci_cd`.

Translations and documentation
==============================

Install gettext for translation commands and Java plus Graphviz for the bundled
PlantUML renderer. The docs environment uses the project's locked dependencies:

.. code-block:: bash

   uv run trustpoint/manage.py makemsg -l de
   uv run trustpoint/manage.py makemsg -l de -d djangojs
   uv run trustpoint/manage.py compilemsg -l de
   uv sync --locked --group docs
   uv run sphinx-build -b html -n -W --keep-going docs/source docs/build/html

Open ``docs/build/html/index.html`` after the build succeeds. A successful build
with warnings is not the same as passing this strict check. Renderer execution
and local test-server ports may need to be permitted by your execution environment.
Do not regenerate autodoc sources over maintained user guides.

To rebuild the workflow editor, see :doc:`../features/workflows/index`.
To add dependencies, use ``uv add <package>`` for runtime imports and
``uv add --dev <package>`` for development-only tools; review both ``pyproject.toml``
and ``uv.lock`` before committing.

Editor configuration
====================

The optional VS Code workspace is ``.vscode/trustpoint.code-workspace``. Open it with
``code .vscode/trustpoint.code-workspace``. Keep personal editor configuration in
ignored local settings; the workspace is not required to run the commands above.
