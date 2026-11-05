=================
Release Checklist
=================

------------------------
Pre-release Preparations
------------------------
- Update version number in :code:`pyproject.toml` and :code:`docs/source/conf.py` files.
- Update :code:`CHANGELOG.md` with new features, fixes, and improvements.
  The final 1.0.0 entry is included in :doc:`../release_notes`. For subsequent
  releases, add a versioned entry describing changes from the stable baseline.
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
- Review ``THIRD_PARTY_LICENSES/README.md`` and its remaining provenance items.
  Run ``npm ci`` and ``npm run check`` in ``trustpoint/workflows2/frontend``.
  Keep complete notices with the distribution. Review the release image's SBOM,
  logo rights and applicable source obligations.

-------
Release
-------
- GitHub Workflow Checks:

  - Review the generated coverage report and coverage regressions. CI retains
    ``coverage.xml`` and test results; no numeric coverage threshold is enforced.
  - Docker build passes.
  - All feature test pass
  - All unit test pass
  - Strict documentation build passes, including rendered-page review:
    ``uv run sphinx-build -b html -n -W --keep-going docs/source docs/build/html``.
  - ZAP's unauthenticated operational baseline completes for both HTTP and HTTPS
    with nonempty JSON/Markdown/HTML reports. Scan errors, missing/malformed
    evidence, medium/high alerts and configured ZAP FAIL results fail the job.
    Informational/low alerts are reported without failing the baseline.
  - Review authenticated operational coverage separately: record the image/commit,
    test role, login method, protected pages/API paths reached, and
    findings/dispositions. Confirm the scanner remains logged in. A green baseline
    covers public/login pages and does not satisfy this authenticated review.
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

Version Identity
----------------

Before creating the release tag, check the installed package, runtime
``APP_VERSION``, UI footer, database ``AppVersion`` after normal startup, and
generated OpenAPI ``info.version`` against ``pyproject.toml`` and ``uv.lock``.
For 1.0.0 these values are ``1.0.0``; the UI display/link and canonical Git and
registry release tags use the ``v1.0.0`` prefix convention.

Both image publishers check project/lockfile agreement and reject Git tags that
do not match ``v<package-version>`` before building or publishing. Stable version
aliases are emitted only for matching Git-tag refs. Main/tag builds may update
``latest``; other branches receive commit tags. The OCI label
``org.opencontainers.image.version`` explicitly contains the raw package version
rather than a moving tag such as ``latest``.

Once the tagged images exist, inspect the actual registry manifests/configs and
confirm the Git commit, image digest, OCI version/revision labels and running
application agree. A configured workflow or local metadata check does not prove
that final publication has occurred. The companion PostgreSQL image uses the
Trustpoint release tag for the deployment bundle; its PostgreSQL server version
remains independent. Do not replace protocol, agent, dependency or fixture
versions merely because they differ from the application version.

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
actual image replacement during the recreation check. Trustpoint 1.0.0 is the
first stable compatibility baseline; cross-version update tests apply to
subsequent explicitly supported releases.

Manual Deployment Acceptance
----------------------------

Record the image digest/commit, Compose file selection, host platform, and actual
result for each scenario. These are outstanding acceptance checks until a result
is recorded for the release version and image; documentation updates do not mark them passed.
Use isolated installations and synthetic data. Never reset an existing deployment
to perform a release smoke test.

* **Interactive setup:** initialize independent secrets, start a fresh stack,
  obtain bootstrap credentials from its logs, and complete every wizard step.
  Confirm operational login, issuance, background processing, and restart without
  returning to the wizard or replacing keys.
* **Custom ports and hostnames:** configure the intended ``TP_TLS_*`` names and
  ``TP_HTTP_PORT`` / ``TP_HTTPS_PORT`` before setup. Confirm initial HTTP redirects
  preserve the intended HTTPS destination, certificate SANs match, login/forms
  pass host/CSRF checks, and protocol URLs use the externally reachable ports.
  Record failures; do not document a redirect/port combination as validated based
  only on Compose accepting its configuration.
* **IPv6:** on a host with working IPv6, configure the address and published-port
  bindings, then verify bracketed URL access, certificate SANs, allowed hosts,
  CSRF-protected forms, enrollment, and CRL retrieval from an IPv6 client.
* **Recovery and updates:** restore a compatible database and its original
  signing/KEK/HSM material into a separate stack. Verify decryption and certificate
  lifecycle operations. For subsequent stable releases, separately test the
  supported previous stable image to new image update; same-image recreation
  does not establish cross-version compatibility.
* **Backend/client matrix:** record real hardware-HSM/provider mechanisms and
  intended EST/CMP/SCEP clients and OPC UA servers. Software or SoftHSM success
  does not establish hardware compatibility. See :doc:`../features/capabilities`.
* **Rendered documentation:** inspect the workflow guide's YAML examples, trigger
  table, and approvals; backup instructions and recovery-key warnings; API endpoint
  paths; and :doc:`../release_notes`. Check important screenshots and external
  links separately from the local strict Sphinx build.
