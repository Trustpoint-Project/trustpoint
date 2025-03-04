.. _ci_cd:

*****
CI/CD
*****

This chapter describes the CI/CD pipelines used in the project.
The pipelines automate various tasks such as testing, building, and deploying.

========
Overview
========

GitHub Actions is used to manage automated workflows.
Below is an overview of the key workflows included in the project:

- **Behave Pipeline**: Runs :term:`behave` tests and uploads the results.
- **Codecov Pipeline**: Runs unit tests via pytest and uploads the test coverage.
- **MyPy Pipeline**: Runs mypy checks and uploads the results.
- **Pytest Pipeline**: Runs unit tests via pytest and uploads the results.
- **Ruff Pipeline**: Runs ruff checks and uploads the results.

===============
Behave Pipeline
===============

.. literalinclude:: ../../.github/workflows/behave-test-template.yml
   :language: yaml

================
Codecov Pipeline
================

.. literalinclude:: ../../.github/workflows/codecov-upload.yml
   :language: yaml

=============
MyPy Pipeline
=============

.. literalinclude:: ../../.github/workflows/mypy.yml
   :language: yaml

===============
Pytest Pipeline
===============

.. literalinclude:: ../../.github/workflows/pytest.yml
   :language: yaml

=============
Ruff Pipeline
=============

.. literalinclude:: ../../.github/workflows/ruff.yml
   :language: yaml