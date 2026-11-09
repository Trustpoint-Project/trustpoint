# Trustpoint documentation

The Sphinx sources in `docs/source/` use reStructuredText and MyST Markdown.

Run from the repository root with a supported Python version, Java, and Graphviz
(`dot`) available:

```sh
uv sync --frozen --group docs
uv run --frozen sphinx-build -b html -n -W --keep-going docs/source docs/build/html
```

Open `docs/build/html/index.html`. For a clean rebuild, add `-E -a`.

The Makefile uses the same project environment:

```sh
make -C docs html SPHINXOPTS="-n -W --keep-going"
make -C docs clean html SPHINXOPTS="-n -W --keep-going"
```

See [Building and editing documentation](source/development/documentation.rst)
for prerequisites, page structure, navigation, and hosted builds.
