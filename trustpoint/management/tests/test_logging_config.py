# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for persisted logging configuration."""

import logging

import pytest

from management.models import LoggingConfig
from management.models.logging import apply_persisted_log_level

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(('stored', 'expected'), [('DEBUG', logging.DEBUG), ('2', logging.WARNING)])
def test_apply_persisted_log_level(stored: str, expected: int) -> None:
    """Apply stored names and legacy numeric values to the root logger."""
    original = logging.getLogger().level
    LoggingConfig.objects.update_or_create(pk=1, defaults={'log_level': stored})
    try:
        apply_persisted_log_level()
        assert logging.getLogger().level == expected
    finally:
        logging.getLogger().setLevel(original)
