# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Serialization helpers for backend capability snapshots."""

import hashlib
import json


def string_tuple(payload: dict[str, object], key: str) -> tuple[str, ...]:
    """Return a tuple of strings from a serialized capability-list field."""
    value = payload.get(key, [])
    if not isinstance(value, list):
        msg = f'Capability field {key!r} must be a list of strings.'
        raise TypeError(msg)

    if not all(isinstance(item, str) for item in value):
        msg = f'Capability field {key!r} must only contain strings.'
        raise ValueError(msg)

    return tuple(value)


def capability_fingerprint(payload: dict[str, object]) -> str:
    """Return a stable snapshot fingerprint."""
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(serialized).hexdigest()
