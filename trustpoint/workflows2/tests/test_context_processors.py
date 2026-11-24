# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for the workflow navigation badge context processor."""

from types import SimpleNamespace
from typing import Any

import pytest

from workflows2 import context_processors


@pytest.fixture(autouse=True)
def clear_cache() -> None:
    """Keep the per-process cache from leaking between tests."""
    context_processors._cache.update(last=0.0, counts={})  # noqa: SLF001


def test_reset_clears_cached_counts() -> None:
    context_processors._cache.update(last=123.0, counts={'workflow_waiting_total': 3})  # noqa: SLF001
    context_processors.reset_waiting_counts_cache()
    assert context_processors._cache == {'last': 0.0, 'counts': {}}  # noqa: SLF001


@pytest.mark.django_db
def test_waiting_counts_are_cached(django_assert_num_queries: Any) -> None:
    """Reuse the counts instead of querying on every page render."""
    request = SimpleNamespace(user=SimpleNamespace(is_authenticated=True))

    with django_assert_num_queries(2):
        first = context_processors.waiting_counts(request)
    with django_assert_num_queries(0):
        second = context_processors.waiting_counts(request)

    assert first == second
    assert first['workflow_waiting_total'] == 0
