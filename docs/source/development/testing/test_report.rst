.. _test_report:

===========
Test Report
===========

Release evidence must identify the tested commit/image, environment, command,
result, skipped cases, and retained logs. A workflow badge is a moving branch
status, not evidence that a particular release passed every check. Record the
exact release results alongside the release notes and use
:doc:`../release-checklist` for the remaining acceptance scenarios.

Automated suites
================

The repository currently provides these workflow entry points:

.. list-table:: Test and analysis workflows
   :header-rows: 1
   :widths: 30 35 35

   * - Area
     - Workflow under ``.github/workflows/``
     - Evidence to inspect
   * - Application pytest
     - ``pytest.yml``
     - Test report, failures, skips, and selected test directories
   * - Behave capability scenarios
     - ``behave.yml`` / ``behave-test-template.yml``
     - Devices, PKI, API, security, and system matrix results
   * - Coverage
     - ``codecov-upload.yml``
     - Measured coverage for the tested commit and actual configured gate
   * - Lint/type/shell checks
     - ``ruff.yml``, ``mypy.yml``, ``shellcheck.yml``
     - Exit status with locked tool versions; formatting is a separate check
   * - Container setup
     - ``docker-test-compose.yml``, ``docker-test-auto-setup.yml``, ``r_200_feature_test.yml``
     - Clean startup, configured setup path, and HTTP/application assertions
   * - Enrollment interoperability
     - ``enrollment-endpoints.yml``
     - Configured OpenSSL/client results and issued certificate assertions
   * - Migration compatibility
     - ``test-migrations-compatibility.yml``
     - Inspect test direction and data assertions; system checks alone do not prove forward upgrades
   * - Backup/restore
     - ``backup-restore.yml``
     - Reusable workflow only; confirm it was actually invoked and had matching secrets
   * - Security analysis
     - ``codeql.yml``, ``zap.yml``, ``sbom.yml``
     - Scan completion, artifacts, findings, and review decisions

The current pytest workflow selects ``trustpoint/``; local complete test runs
must also include root ``tests/`` utilities. The capability matrix replaces the
old per-requirement ``r_001`` through ``r_104`` badge links. Requirement tags remain
in feature files; they do not imply separate hosted workflows still exist.

Environment and failure triage
==============================

Follow :ref:`trustpoint_dev_env_setup` for interpreter, database, and synthetic
KEK setup. Follow :ref:`ci_cd` for workflow definitions. Distinguish implementation
failures from test/configuration/environment problems and record the rerun that
supports that classification. Never discard the original failed result.

In particular:

* Networking tests require permission to bind local sockets.
* SQLite skips genuine PostgreSQL locking/concurrency behavior.
* PKCS#11 and real GDS tests require their provider/server configuration.
* URL-validation utility tests currently include live-DNS assumptions.
* On macOS, temporary-file group ownership can affect initializer fixtures.

Acceptance and release record
=============================

For each release, record:

* the exact commit, package version, image digest, platform, and configuration;
* counts of passed/failed/skipped tests, including why integration cases skipped;
* documentation, dependency, container, and security scan results;
* clean-install, interactive setup, update, and original-key restore results;
* real client/provider/server combinations exercised;
* unresolved defects, accepted limitations, and maintainer approval.

See :doc:`../../release_notes` for the release compatibility baseline and
:doc:`../../features/capabilities` for limitations. This page does not announce
acceptance, infer end-user approval, or mark unexecuted release checks as passed.
