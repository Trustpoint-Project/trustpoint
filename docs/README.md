# Python Documentation README

This directory contains the reStructuredText (reST) sources to the Trustpoint documentation.

## Building the docs

### Using make

```
make html
```

_or_ 

```
make clean html
```
_for building without cache_

Use
```
uv run -m sphinx.cmd.build -M html source build
```
for forcing use of the correct env if you get a `Cannot import trustpoint.settings` error.