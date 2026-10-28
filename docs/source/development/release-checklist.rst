=================
Release Checklist
=================

------------------------
Pre-release Preparations
------------------------
- Update version number in :code:`pyproject.toml` and :code:`docs/source/conf.py` files.
- Update :code:`CHANGELOG.md` with new features, fixes, and improvements.
- Review :code:`pyproject.toml`
  - Update dependencies if needed.
  - Pin versions for production stability in :code:`uv.lock`
- Update documentation (:code:`README.md`, API docs, usage instructions) for new features. 
- Ensure all new migrations are created, committed, tested locally.
  Multiple migration files for the same release can be necessary to resolve
  dependencies between apps. Squash only when the resulting graph remains acyclic.
  For published migrations, keep the original files alongside squashed replacements
  until deployed databases have completed the transition. For a fresh-install
  baseline, remove replaced files only after updating all dependencies and removing
  the squashed migration's ``replaces`` attribute.
- Verify migrations on a fresh database and check for pending model changes.

-------
Release
-------
- GitHub Workflow Checks
  - Code coverage threshold maintained ( >85%).
  - Docker build passes.
  - All feature test pass
  - All unit test pass
  - Read the docs build passes
  - SBOM generation passes
  - Code linter (:code:`ruff` and :code:`mypy`) tests pass
  - No new deprecations from Django or libraries in test logs.
- Create git tag for release

------------
Post-Release
------------

- `Trustpoint Docker Hub <https://hub.docker.com/u/trustpointproject>`_ Account
  - Tag the docker image with release tag and push to the Docker Hub
  - Update the README.md on the Docker Hub if required
- Update `Trustpoint website <https://trustpoint.campus-schwarzwald.de/en/>`_ with release information.

Docker Deployment Validation
----------------------------

Run the Compose and secret-initializer unit tests, then build an isolated test
image and exercise a fresh web/worker deployment. The smoke test uses synthetic
data, temporary named volumes, and no published ports; it cleans up its own project.

.. code-block:: bash

   uv run pytest trustpoint/setup_wizard/tests/test_secret_initialization.py trustpoint/setup_wizard/tests/test_docker_deployment.py
   docker build -t trustpoint-compose-regression:local -f docker/trustpoint/Dockerfile .
   python3 tests/docker_security/compose_smoke.py

To include the optional SoftHSM service and worker profile:

.. code-block:: bash

   docker build -t trustpoint-softhsm-regression:local -f docker/softhsm/Dockerfile .
   TRUSTPOINT_TEST_COMPOSE_FILE=docker-compose.softhsm.yml python3 tests/docker_security/compose_smoke.py

To exercise real software and SoftHSM envelopes inside the application image
without using the deployment's database or secrets:

.. code-block:: bash

   docker run --rm --network=none --user 33:33 \
     --entrypoint /var/www/html/trustpoint/.venv/bin/python \
     --mount type=bind,src="$PWD/tests/docker_security/envelope_smoke.py",dst=/tests/envelope_smoke.py,readonly \
     trustpoint-compose-regression:local /tests/envelope_smoke.py software
   # Repeat with the final argument pkcs11 for a fresh synthetic SoftHSM token.

The Compose regression checks a shared DEK across web and worker processes,
read-only secret mounts, restart/recreation, and simultaneous PostgreSQL DEK
initialization. The standalone SoftHSM-stack auto-setup test still exercises
software storage; the ``pkcs11`` envelope regression verifies actual HSM-backed
DEK protection without any software KEK.

Set ``TRUSTPOINT_TEST_IMAGE`` to the initial test image and
``TRUSTPOINT_TEST_UPGRADE_IMAGE`` to a second compatible test image to include an
actual image replacement during the recreation check. Do not use pre-1.0 images
for this test: encrypted database migration from those releases is unsupported.
