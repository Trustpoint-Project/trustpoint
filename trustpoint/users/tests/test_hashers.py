# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the fast service-account secret hasher."""

from django.contrib.auth.hashers import check_password, make_password


def test_unsalted_sha256_roundtrip() -> None:
    """The fast hasher accepts the right secret and rejects a wrong one."""
    encoded = make_password('a' * 64, hasher='unsalted_sha256')

    assert encoded.startswith('unsalted_sha256$')
    assert check_password('a' * 64, encoded) is True
    assert check_password('b' * 64, encoded) is False
