# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
"""Regression tests for Dashboard certificate classification."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from home.metrics import certificate_health_counts, classify_certificate

NOW = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ('start_offset', 'end_offset', 'revoked', 'expected'),
    [
        (-10, 90, False, 'valid'),
        (-10, 5, False, 'expiring'),
        (-10, 30, False, 'expiring'),
        (-10, -1, False, 'expired'),
        (1, 90, False, 'not_yet_valid'),
        (-10, 5, True, 'revoked'),
        (1, 90, True, 'revoked'),
        (-10, 0, False, 'expired'),
        (0, 90, False, 'valid'),
    ],
)
def test_classification(start_offset: int, end_offset: int, revoked: bool, expected: str) -> None:
    assert classify_certificate(
        not_valid_before=NOW + timedelta(days=start_offset),
        not_valid_after=NOW + timedelta(days=end_offset),
        revoked=revoked,
        as_of=NOW,
    ) == expected


def test_expiry_horizon_changes_category() -> None:
    certificate = dict(not_valid_before=NOW - timedelta(days=1), not_valid_after=NOW + timedelta(days=20), revoked=False, as_of=NOW)
    assert classify_certificate(**certificate, expiry_days=7) == 'valid'
    assert classify_certificate(**certificate, expiry_days=30) == 'expiring'


def test_rejects_invalid_horizon() -> None:
    with pytest.raises(ValueError, match='expiry_days'):
        classify_certificate(not_valid_before=NOW, not_valid_after=NOW + timedelta(days=2), revoked=False, as_of=NOW, expiry_days=2)


def test_requires_aware_reference_time() -> None:
    with pytest.raises(ValueError, match='timezone-aware'):
        classify_certificate(not_valid_before=NOW, not_valid_after=NOW + timedelta(days=2), revoked=False, as_of=NOW.replace(tzinfo=None))


def test_aggregate_uses_single_as_of_and_preserves_consistency() -> None:
    queryset = Mock()
    queryset.aggregate.return_value = {
        'total': 8,
        'valid': 3,
        'expiring': 2,
        'expired': 1,
        'revoked': 1,
        'not_yet_valid': 1,
    }
    result = certificate_health_counts(queryset, as_of=NOW, expiry_days=30)
    assert result['total'] == 8
    assert result['expiring'] == 2
    assert result['active'] == 5
    assert result['unclassified'] == 0
    assert result['as_of'] == NOW.isoformat()
    assert queryset.aggregate.call_count == 1


def test_unclassified_not_silently_ignored() -> None:
    queryset = Mock()
    queryset.aggregate.return_value = dict(total=2, valid=0, expiring=0, expired=0, revoked=0, not_yet_valid=1)
    assert certificate_health_counts(queryset, as_of=NOW)['unclassified'] == 1
