# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for managed-key unwrapping helpers."""

from __future__ import annotations

import uuid

from crypto.application.private_keys import ManagedECPrivateKey, ManagedRSAPrivateKey
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import SigningExecutionMode
from crypto.domain.refs import ManagedKeyRef
from pki.util import x509 as x509_util


def _managed_key_ref(*, algorithm: KeyAlgorithm, alias: str) -> ManagedKeyRef:
    """Build a minimal managed-key ref for wrapper construction in tests."""
    return ManagedKeyRef(
        id=uuid.uuid4(),
        alias=alias,
        algorithm=algorithm,
        public_key_fingerprint_sha256='0' * 64,
        signing_execution_mode=SigningExecutionMode.COMPLETE_BACKEND,
    )


def test_unwrap_mldsa_managed_key_keeps_managed_rsa_facade(monkeypatch) -> None:
    """Managed RSA facade must not be unwrapped to software key material."""
    managed_rsa_key = ManagedRSAPrivateKey(key_ref=_managed_key_ref(algorithm=KeyAlgorithm.RSA, alias='rsa-managed'))

    monkeypatch.setattr(
        x509_util.CryptoManagedKeyModel.objects,
        'get',
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('DB lookup should not happen for RSA')),  # noqa: ARG005
    )

    assert x509_util._unwrap_mldsa_managed_key(managed_rsa_key) is managed_rsa_key


def test_unwrap_mldsa_managed_key_keeps_managed_ec_facade(monkeypatch) -> None:
    """Managed EC facade must not be unwrapped to software key material."""
    managed_ec_key = ManagedECPrivateKey(key_ref=_managed_key_ref(algorithm=KeyAlgorithm.EC, alias='ec-managed'))

    monkeypatch.setattr(
        x509_util.CryptoManagedKeyModel.objects,
        'get',
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('DB lookup should not happen for EC')),  # noqa: ARG005
    )

    assert x509_util._unwrap_mldsa_managed_key(managed_ec_key) is managed_ec_key
