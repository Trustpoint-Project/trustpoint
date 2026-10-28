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
