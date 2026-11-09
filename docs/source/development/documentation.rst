Building and editing documentation
==================================

The documentation lives in ``docs/source/`` and uses Sphinx with the Furo theme.
Pages can use reStructuredText (``.rst``) or MyST Markdown (``.md``). Run the
commands below from the repository root.

Build locally
-------------

Use a Python version supported by ``pyproject.toml`` and install the locked
documentation dependencies:

.. code-block:: console

   uv sync --frozen --group docs

Install a Java runtime and Graphviz (including the ``dot`` command) for diagram
rendering. Sphinx uses the PlantUML JAR checked into ``docs/source/``; a separate
PlantUML installation is not needed locally. Check that both tools are on your
``PATH``:

.. code-block:: console

   java -version
   dot -V

Build HTML with unresolved-reference checks and warnings treated as errors:

.. code-block:: console

   uv run --frozen sphinx-build -b html -n -W --keep-going docs/source docs/build/html

Open ``docs/build/html/index.html`` in a browser. For a clean rebuild, add
``-E -a`` to the command. To use the Makefile from the repository root:

.. code-block:: console

   make -C docs html SPHINXOPTS="-n -W --keep-going"
   make -C docs clean html SPHINXOPTS="-n -W --keep-going"

The build initializes Django through ``docs/source/conf.py``, so it needs the
project environment, not just a standalone Sphinx installation. It does not
require a running application, database migrations, or a database reset.

Page structure and navigation
-----------------------------

Give each page one title. In Markdown, use one ``#`` heading followed by ``##``
sections and ``###`` subsections. In reStructuredText, use consistent heading
adornments to express the same hierarchy. Do not paste reStructuredText headings
or directives into a Markdown page; use MyST directives instead:

.. code-block:: markdown

   # Page title

   ## Section

   ```{note}
   A note written in MyST Markdown.
   ```

Add new pages to the appropriate ``toctree``. Development guides are grouped in
:doc:`overview`; architecture pages are listed in :doc:`architecture/index`.
Link to local source documents with relative paths or Sphinx ``doc``/``ref``
roles, so links also work in local builds and hosted versions. Preserve existing
page paths and explicit reference labels when reorganizing content.

After editing, run the strict HTML build and inspect the affected pages in a
browser. Check the sidebar hierarchy, page contents, code blocks, admonitions,
and section links. For the interface guidelines, also check the
:ref:`light-and-dark-mode` section link. Generated architecture pages are
maintained separately; do not overwrite maintained guides with generated output.

Hosted builds
-------------

Read the Docs uses ``.readthedocs.yaml`` to select Python, install the frozen
documentation dependencies, and provide diagram tools. Sphinx enables
unresolved-reference warnings in ``conf.py``, and the hosted configuration treats
warnings as build failures. Pull-request previews depend on the Read the Docs
project's integration settings. See :doc:`testing/ci_cd` for the full build
configuration.
