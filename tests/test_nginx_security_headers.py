# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Guard Nginx proxy header inheritance on plaintext enrollment locations."""

# ruff: noqa: INP001

from pathlib import Path

import pytest

CONFIG = Path(__file__).resolve().parents[1] / 'docker/trustpoint/nginx/trustpoint-nginx-https.conf'


@pytest.mark.parametrize('location', ['/crl/', '/.well-known/cmp/', '/.well-known/scep/'])
def test_http_enrollment_inherits_all_sanitized_proxy_headers(location: str) -> None:
    """A local proxy_set_header drops all server-level TLS/header sanitization."""
    http_server = CONFIG.read_text().split('# HTTP server', 1)[1].split('# HTTPS server', 1)[0]
    server_headers = http_server.split('    location ', 1)[0]
    for header in [
        'SSL-Client-Cert ""',
        'X-SSL-Client-Verify "NONE"',
        'X-SSL-Client-S-DN ""',
        'X-EST-TLS-Unique ""',
        'X-EST-TLS-Unique-Supported "0"',
        'X-EST-TLS-Protocol ""',
        'X-Forwarded-Proto $scheme',
        'Host $http_host',
    ]:
        assert f'proxy_set_header {header};' in server_headers
    body = http_server.split(f'location {location} {{', 1)[1].split('}', 1)[0]
    assert 'proxy_pass http://127.0.0.1:8000;' in body
    assert 'proxy_set_header' not in body


def test_https_channel_binding_headers_are_derived_from_tls() -> None:
    """Overwrite client-supplied assertions with data from the nginx TLS module."""
    https_server = CONFIG.read_text().split('# HTTPS server', 1)[1]
    for header in [
        'X-EST-TLS-Unique $trustpoint_tls_unique',
        'X-EST-TLS-Unique-Supported $trustpoint_tls_unique_supported',
        'X-EST-TLS-Protocol $ssl_protocol',
    ]:
        assert f'proxy_set_header {header};' in https_server
