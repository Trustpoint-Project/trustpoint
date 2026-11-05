# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Reproduce the self-hosted ReDoc asset with nonce support before style loading."""

# ruff: noqa: INP001, T201

import argparse
from importlib.util import find_spec
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
YASG_SPEC = find_spec('drf_yasg')
assert YASG_SPEC, 'Install the locked runtime dependencies'
assert YASG_SPEC.origin
SOURCE = Path(YASG_SPEC.origin).parent / 'static/drf-yasg/redoc'
DESTINATION = ROOT / 'trustpoint/static/js/redoc-csp.min.js'


def build(*, check: bool) -> None:
    """Apply two explicit substitutions; reject changed upstream bundle structure."""
    content = (SOURCE / 'redoc.min.js').read_text()
    changes = {
        'r.nc=void 0': 'r.nc=document.currentScript.nonce',
        'https://cdn.redoc.ly/redoc/logo-mini.svg': '/static/drf-yasg/redoc/redoc-logo.png',
    }
    for original, replacement in changes.items():
        assert content.count(original) == 1, f'Upstream ReDoc changed: review {original}'
        content = content.replace(original, replacement)
    content = content.replace('//# sourceMappingURL=redoc.standalone.js.map', '')
    banner = '/*! ReDoc: see redoc-csp.min.js.NOTICES.txt; reproduce with tests/scripts/build_redoc_csp.py */\n'
    content = banner + content
    outputs = {DESTINATION: content, Path(str(DESTINATION) + '.NOTICES.txt'): (SOURCE / 'LICENSE').read_text()}
    for destination, value in outputs.items():
        if check:
            assert destination.read_text() == value, f'Stale ReDoc asset: {destination}'
        else:
            destination.write_text(value)
    print('ReDoc CSP asset matches installed drf-yasg' if check else 'Built ReDoc CSP asset')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    build(check=parser.parse_args().check)
