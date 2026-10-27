# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Validate CRL URLs and the supported issuance-time placeholders."""

import re
from urllib.parse import urlsplit

CRL_PLACEHOLDER = re.compile(r'\{\{\s*(issuing_ca\.id|tls_certificate\.ip_address\.[1-9][0-9]*)\s*\}\}|'
                             r'\{(issuing_ca\.id|tls_certificate\.ip_address\.[1-9][0-9]*)\}')


def validate_crl_url(value: str) -> str:
    """Validate an absolute CRL URL, optionally containing supported placeholders."""
    candidate = CRL_PLACEHOLDER.sub('1', value)
    try:
        candidate.encode('ascii')
        parsed = urlsplit(candidate)
        valid = bool(parsed.scheme and parsed.netloc and parsed.hostname)
        _ = parsed.port
    except (ValueError, UnicodeError):
        valid = False
    if not valid or any(c.isspace() or c in '{}' for c in candidate):
        msg = ('CRL URLs must be absolute ASCII URLs (for example http://2.2.2.2/crl/{issuing_ca.id}). '
               'Supported placeholders: {issuing_ca.id} and {tls_certificate.ip_address.N} (1-based).')
        raise ValueError(msg)
    return value
