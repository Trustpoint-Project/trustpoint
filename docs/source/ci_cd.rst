.. _ci_cd:

*****
CI/CD
*****

This chapter describes the CI/CD pipelines used in the project.
The pipelines automate various tasks such as testing, building, and deploying.

========
Overview
========

GitHub Actions are used to manage automated workflows.
Below is an overview of the key workflows included in the project:

- **Behave Pipeline**: Runs :term:`behave` tests and uploads the results.
- **Codecov Pipeline**: Runs unit tests via pytest and uploads the test coverage.
- **Pytest Pipeline**: Runs unit tests via pytest and uploads the results.
- **MyPy Pipeline**: Runs mypy checks and uploads the results.
- **Ruff Pipeline**: Runs ruff checks and uploads the results.

-------------------------------
Sequence Diagram CI/CD Pipeline
-------------------------------

.. plantuml:: diagrams/sequence_pipeline.puml
    :caption: Sequence Diagram of the automatically triggered pipelines

--------------------------------
Component Diagram CI/CD Pipeline
--------------------------------

.. plantuml:: diagrams/component_pipeline.puml
    :caption: Component Diagram of the automatically triggered pipelines

.. _composite_setup_action:

======================
Composite Setup action
======================

Since we are using :term:`uv` as package manager and the setup is the same everytime,
it makes sense to create a separate action that can be used from every other action.
The so called `"composite action" <https://docs.github.com/en/actions/sharing-automations/creating-actions/creating-a-composite-action>`_
looks like the following:

.. literalinclude:: ../../.github/actions/setup-uv-action/action.yml
    :language: yaml
    :caption: Setup uv composite action

As said, this action sets up the environment by installing :term:`uv` via Astrals github action
`setup-uv <https://github.com/marketplace/actions/astral-sh-setup-uv>`_ and uses a pinned version, as well as caching.
After this, the `setup-python <https://github.com/actions/setup-python>`_ action
is called which takes the python version from the pyproject file.
At the time of writing this, that action may be faster than uv's own action because of GitHubs caching mechanism.
The action ends with maybe running database migrations depending on the switch provided by the input ``run_migrations``.

===============
Behave Pipeline
===============

The following workflow file is a reusable template workflow
because we want to have exactly one result for every feature file executed.
That is to show the progress inside the README.md file which features are working and which do not work just yet.
This workflow template uses a string as an input value which just specifies which feature file to run.
First of all, we checkout the code via `actions/checkout <https://github.com/actions/checkout>`_.
Then, we are using the previously defined action (see :ref:`composite_setup_action`) to make :term:`uv` usable inside this workflow.
Having :term:`uv` activated, the behave action is triggered for the given feature file.
Note that we need to use ``uv run trustpoint/manage.py behave`` instead of ``uv run behave`` to make :term:`Django` available for behave.
Once the tests are ran, an artifact with the test reports is uploaded.

.. literalinclude:: ../../.github/workflows/behave-test-template.yml
    :language: yaml
    :caption: Behave template workflow

We provide an example on how to use this workflow below:

.. literalinclude:: ../../.github/workflows/r_013_feature_test.yml
    :language: yaml
    :caption: R_013 workflow

.. _codecov_pipeline:

================
Codecov Pipeline
================

We are using `Codecov <https://about.codecov.io/>`_ for analyzing our pytest code coverage and showing this with a badge.
This workflow is also setting up :term:`uv` as in :ref:`composite_setup_action`
and using it to run pytest with a coverage report which will be uploaded to codecov in the next step.

.. literalinclude:: ../../.github/workflows/codecov-upload.yml
    :language: yaml
    :caption: Upload to codecov workflow

===============
Pytest Pipeline
===============

This pipeline/workflow is kind of the same as `the one above <codecov_pipeline>`_
except from not running the coverage reports and therefore also not uploading them.
Here, we use a git flavored markdown report for printing the report nicely to the job summary.
After this, there is the full report uploaded first and lastly,
if one or more tests fail,
we add a comment to the current pull request.

.. literalinclude:: ../../.github/workflows/pytest.yml
    :language: yaml
    :caption: Pytest workflow

.. _mypy_pipeline:

=============
MyPy Pipeline
=============

We use :term:`mypy` for static type checking in python.
This pipeline is actually really short because it just sets up :term:`uv` from :ref:`composite_setup_action` and then runs mypy.

.. literalinclude:: ../../.github/workflows/mypy.yml
    :language: yaml
    :caption: mypy workflow

=============
Ruff Pipeline
=============

Also, the ruff action is nearly as short as the :ref:`mypy_pipeline`.
The only difference is that we now run :term:`ruff` and upload the report if there are any errors.

.. literalinclude:: ../../.github/workflows/ruff.yml
    :language: yaml
    :caption: ruff workflow
