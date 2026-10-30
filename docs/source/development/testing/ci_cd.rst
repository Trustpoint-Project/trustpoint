.. _ci_cd:

*****
CI/CD
*****

.. |pytest-badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml/badge.svg
   :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/pytest.yml

.. |codecov-badge| image:: https://codecov.io/gh/Trustpoint-Project/trustpoint/graph/badge.svg?token=0N31L1QWPE
   :target: https://codecov.io/gh/Trustpoint-Project/trustpoint

.. |mypy-badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml/badge.svg
   :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/mypy.yml

.. |ruff-badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml/badge.svg
   :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/ruff.yml

.. |codeql-badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/codeql.yml/badge.svg
   :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/codeql.yml

.. |zap-badge| image:: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/zap.yml/badge.svg
   :target: https://github.com/Trustpoint-Project/trustpoint/actions/workflows/zap.yml

This chapter describes the CI/CD pipelines used in the project.
The pipelines automate various tasks such as testing, building, and deploying.

========
Overview
========

GitHub Actions and Read the Docs manage the automated workflows.
Below is an overview of the key workflows included in the project:

- **Documentation Pipeline**: Builds HTML with strict references and treats warnings as failures.
- **Behave Pipeline**: Runs :term:`behave` tests and uploads the results.
- **Codecov Pipeline**: Runs unit tests via pytest and uploads the test coverage. |codecov-badge|
- **CodeQL Pipeline**: Runs CodeQL security analysis on the codebase. |codeql-badge|
- **Pytest Pipeline**: Runs unit tests via pytest and uploads the results. |pytest-badge|
- **mypy Pipeline**: Runs :term:`mypy` checks and uploads the results. |mypy-badge|
- **Ruff Pipeline**: Runs :term:`ruff` checks and uploads the results. |ruff-badge|
- **ZAP Pipeline**: Runs OWASP ZAP security scans on the web application. |zap-badge|

-------------------------------
Sequence Diagram CI/CD Pipeline
-------------------------------

.. plantuml:: ../../diagrams/sequence_pipeline.puml
    :caption: Sequence Diagram of the automatically triggered pipelines

--------------------------------
Component Diagram CI/CD Pipeline
--------------------------------

.. plantuml:: ../../diagrams/component_pipeline.puml
    :caption: Component Diagram of the automatically triggered pipelines

.. _composite_setup_action:

======================
Composite Setup action
======================

Since we are using :term:`uv` as package manager and the setup is the same everytime,
it makes sense to create a separate action that can be used from every other action.
The so called `"composite action" <https://docs.github.com/en/actions/sharing-automations/creating-actions/creating-a-composite-action>`_
looks like the following:

.. literalinclude:: ../../../../.github/actions/setup-uv-action/action.yml
    :language: yaml
    :caption: Setup uv composite action

As said, this action sets up the environment by installing :term:`uv` via Astrals github action
`setup-uv <https://github.com/marketplace/actions/astral-sh-setup-uv>`_ and uses a pinned version, as well as caching.
After this, the `setup-python <https://github.com/actions/setup-python>`_ action
is called with the shared action's ``python-version`` input (currently Python 3.14),
matching the Docker runtime. ``pyproject.toml`` defines the supported minimum, not
that CI input.
At the time of writing this, that action may be faster than uv's own action because of GitHubs caching mechanism.
With ``run_migrations=true``, the action provisions a synthetic software KEK for
the job and resets its disposable database while preserving tracked migrations.
That destructive setup is for isolated CI, not an installation or upgrade recipe.

======================
Documentation Pipeline
======================

Read the Docs builds and publishes the documentation using the repository's
``.readthedocs.yaml`` configuration. It installs the frozen documentation
dependencies with uv and provides Java/PlantUML and Graphviz for diagrams.
``sphinx.fail_on_warning: true`` makes documentation warnings fail the hosted
build, and ``nitpicky = True`` in ``docs/source/conf.py`` enables unresolved
reference warnings for both hosted and local builds. No database reset is required.
Pull-request previews and build-status reporting depend on the Read the Docs
project's integration settings.

.. literalinclude:: ../../../../.readthedocs.yaml
    :language: yaml
    :caption: Read the Docs configuration

===============
Behave Pipeline
===============

The following workflow file is a reusable template workflow
with one result per capability directory selected by the matrix.
The template accepts a path below ``trustpoint/features/`` and uploads a report
for the selected scenarios.
First of all, we checkout the code via `actions/checkout <https://github.com/actions/checkout>`_.
Then, we are using the previously defined action (see :ref:`composite_setup_action`) to make :term:`uv` usable inside this workflow.
Having :term:`uv` activated, the behave action is triggered for the given feature file.
Note that we need to use ``uv run trustpoint/manage.py behave`` instead of ``uv run behave`` to make :term:`Django` available for behave.
Once the tests are ran, an artifact with the test reports is uploaded.

.. literalinclude:: ../../../../.github/workflows/behave-test-template.yml
    :language: yaml
    :caption: Behave template workflow

We provide an example on how to use this workflow below:

.. literalinclude:: ../../../../.github/workflows/behave.yml
    :language: yaml
    :caption: Behave capability matrix

.. _codecov_pipeline:

================
Codecov Pipeline
================

We are using `Codecov <https://about.codecov.io/>`_ for analyzing our pytest code coverage and showing this with a badge.
This workflow is also setting up :term:`uv` as in :ref:`composite_setup_action`
and using it to run pytest with a coverage report which will be uploaded to codecov in the next step.

.. literalinclude:: ../../../../.github/workflows/codecov-upload.yml
    :language: yaml
    :caption: Upload to codecov workflow

===============
Pytest Pipeline
===============

This pipeline/workflow is kind of the same as :ref:`the coverage pipeline <codecov_pipeline>`
except from not running the coverage reports and therefore also not uploading them.
Here, we use a git flavored markdown report for printing the report nicely to the job summary.
After this, there is the full report uploaded first and lastly,
if one or more tests fail,
we add a comment to the current pull request.

.. literalinclude:: ../../../../.github/workflows/pytest.yml
    :language: yaml
    :caption: Pytest workflow

.. _mypy_pipeline:

=============
mypy Pipeline
=============

We use :term:`mypy` for static type checking in python.
This pipeline sets up :term:`uv` through :ref:`composite_setup_action` and runs
``uv run --frozen mypy .`` in the locked project environment, matching the local hook.

.. literalinclude:: ../../../../.github/workflows/mypy.yml
    :language: yaml
    :caption: mypy workflow

=============
Ruff Pipeline
=============

Also, the :term:`ruff` action is nearly as short as the :ref:`mypy_pipeline`.
It runs ``uv run --frozen ruff check .`` across the repository. On pull requests,
it also runs the Ruff formatter in check mode on added or modified Python files,
honoring project exclusions. Pre-commit checks staged Python files using the same
locked tools. Untouched legacy formatting is deferred to a separate cleanup;
there is no repository-wide format gate.

.. literalinclude:: ../../../../.github/workflows/ruff.yml
    :language: yaml
    :caption: ruff workflow

===============
CodeQL Pipeline
===============

We use `CodeQL <https://codeql.github.com/>`_ for automated security analysis of the codebase.
This pipeline runs CodeQL analysis on multiple languages including Python, JavaScript/TypeScript, and GitHub Actions.
It performs static analysis to identify potential security vulnerabilities and code quality issues.
The analysis is configured with a custom CodeQL configuration file and runs on a schedule as well as on pushes and pull requests to the main branch.

.. literalinclude:: ../../../../.github/workflows/codeql.yml
    :language: yaml
    :caption: CodeQL workflow

============
ZAP Pipeline
============

We use `OWASP ZAP <https://www.zaproxy.org/>`_ (Zed Attack Proxy) for automated security scanning of the web application.
This pipeline performs baseline security scans on both HTTP and HTTPS endpoints of the running Trustpoint application.
It starts the application using Docker Compose, runs ZAP scans on ports 80 (HTTP) and 443 (HTTPS), and uploads the scan reports as artifacts.
The final step counts ``FAIL-NEW`` and ``WARN-NEW`` entries in available reports.
Scan steps currently allow errors, and absent reports are not rejected by that
final step. Inspect scan completion and artifacts before treating a green job as
security evidence. It is not an authenticated operational-coverage guarantee.

.. literalinclude:: ../../../../.github/workflows/zap.yml
    :language: yaml
    :caption: ZAP workflow
