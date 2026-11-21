# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the lenient REST JSON parser."""

from io import BytesIO

import pytest
from rest_framework.exceptions import ParseError

from rest_pki.api_views import LenientJSONParser


def test_literal_newline_inside_string_is_accepted() -> None:
    """PEM blocks pasted with real newlines are accepted without rewriting."""
    body = b'{"csr": "-----BEGIN CERTIFICATE REQUEST-----\\nline two\\n-----END CERTIFICATE REQUEST-----"}'
    raw_body = body.replace(b'\\n', b'\n')

    assert LenientJSONParser().parse(BytesIO(raw_body)) == {
        'csr': '-----BEGIN CERTIFICATE REQUEST-----\nline two\n-----END CERTIFICATE REQUEST-----'
    }


def test_invalid_json_raises_parse_error() -> None:
    """Malformed JSON still fails as a normal DRF parse error."""
    with pytest.raises(ParseError):
        LenientJSONParser().parse(BytesIO(b'{not json}'))
