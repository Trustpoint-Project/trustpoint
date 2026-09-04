"""Tests for PKI security-policy strategies."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from trustpoint_core.oid import PublicKeyAlgorithmOid

from pki.authorization import (
    PkiSecurityAuthorization,
    _AllowSelfSignedCaStrategy,
    _MaxCrlValidityStrategy,
    _NotPermittedEccCurvesStrategy,
    _NotPermittedSignatureAlgorithmsStrategy,
    _RsaMinimumKeySizeStrategy,
)


def ca(certificate: object | None = None, **values: object) -> SimpleNamespace:
    """Build a small CA-shaped object for strategy unit tests."""
    return SimpleNamespace(unique_name='test-ca', ca_certificate_model=certificate, **values)


def certificate(**values: object) -> SimpleNamespace:
    """Build certificate metadata consumed by policy strategies."""
    defaults = {
        'is_self_signed': False,
        'spki_algorithm_oid': PublicKeyAlgorithmOid.RSA.dotted_string,
        'spki_key_size': 2048,
        'spki_ec_curve_oid': '',
        'signature_algorithm_oid': '1.2.840.113549.1.1.11',
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def config(**values: object) -> SimpleNamespace:
    """Build a security policy object with permissive defaults."""
    defaults = {
        'allow_self_signed_ca': True,
        'max_crl_validity_days': None,
        'rsa_minimum_key_size': 2048,
        'not_permitted_ecc_curve_oids': [],
        'not_permitted_signature_algorithm_oids': [],
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_self_signed_policy_allows_or_rejects_certificates() -> None:
    """Self-signed policy accepts or rejects certificates as configured."""
    strategy = _AllowSelfSignedCaStrategy()
    self_signed_ca = ca(certificate(is_self_signed=True))

    strategy.check(self_signed_ca, config(allow_self_signed_ca=True))
    with pytest.raises(ValueError, match='self-signed'):
        strategy.check(self_signed_ca, config(allow_self_signed_ca=False))
    strategy.check(ca(), config(allow_self_signed_ca=False))
    strategy.check(ca(certificate()), config(allow_self_signed_ca=False))


def test_max_crl_validity_enforces_days_and_handles_unconfigured_limit() -> None:
    """CRL validity is compared with the configured day limit."""
    strategy = _MaxCrlValidityStrategy()
    strategy.check(ca(crl_validity_hours=48), config(max_crl_validity_days=2))
    strategy.check(ca(crl_validity_hours=24), config(max_crl_validity_days=2))
    strategy.check(ca(crl_validity_hours=999), config(max_crl_validity_days=None))

    with pytest.raises(ValueError, match='exceeds'):
        strategy.check(ca(crl_validity_hours=48.1), config(max_crl_validity_days=2))


@pytest.mark.parametrize(('minimum',), [(0,), (2048,)])
def test_rsa_key_size_strategy_allows_zero_or_sufficient_size(minimum: int) -> None:
    """RSA policy accepts disabled and sufficient minimum sizes."""
    _RsaMinimumKeySizeStrategy().check(
        ca(certificate(spki_key_size=2048)), config(rsa_minimum_key_size=minimum)
    )


def test_rsa_key_size_strategy_rejects_forbidden_or_weak_keys() -> None:
    """RSA policy rejects forbidden algorithms and undersized keys."""
    strategy = _RsaMinimumKeySizeStrategy()
    with pytest.raises(ValueError, match='not permitted'):
        strategy.check(ca(certificate()), config(rsa_minimum_key_size=None))
    with pytest.raises(ValueError, match='below'):
        strategy.check(ca(certificate(spki_key_size=1024)), config(rsa_minimum_key_size=2048))
    strategy.check(ca(certificate(spki_algorithm_oid=PublicKeyAlgorithmOid.ECC.dotted_string)), config())
    strategy.check(ca(), config(rsa_minimum_key_size=None))


def test_ecc_curve_strategy_checks_blocked_and_allowed_curves() -> None:
    """ECC policy rejects blocked curve OIDs and skips allowed curves."""
    strategy = _NotPermittedEccCurvesStrategy()
    ecc = certificate(
        spki_algorithm_oid=PublicKeyAlgorithmOid.ECC.dotted_string,
        spki_ec_curve_oid='1.2.840.10045.3.1.7',
    )
    strategy.check(ca(ecc), config(not_permitted_ecc_curve_oids=[]))
    strategy.check(ca(ecc), config(not_permitted_ecc_curve_oids=['1.2.3.4']))
    with pytest.raises(ValueError, match='not permitted'):
        strategy.check(ca(ecc), config(not_permitted_ecc_curve_oids=[ecc.spki_ec_curve_oid]))
    strategy.check(ca(certificate()), config(not_permitted_ecc_curve_oids=['1.2.3.4']))
    strategy.check(ca(), config(not_permitted_ecc_curve_oids=['1.2.3.4']))


def test_signature_algorithm_strategy_handles_unknown_and_blocked_hashes() -> None:
    """Signature policy handles unknown, allowed, and blocked algorithms."""
    strategy = _NotPermittedSignatureAlgorithmsStrategy()
    strategy.check(ca(), config(not_permitted_signature_algorithm_oids=['2.3.4']))
    strategy.check(
        ca(certificate(signature_algorithm_oid='2.3.4')),
        config(not_permitted_signature_algorithm_oids=['2.3.4']),
    )
    with pytest.raises(ValueError, match='not permitted'):
        strategy.check(
            ca(certificate()),
            config(not_permitted_signature_algorithm_oids=['2.16.840.1.101.3.4.2.1']),
        )
    strategy.check(
        ca(certificate()),
        config(not_permitted_signature_algorithm_oids=['2.16.840.1.101.3.4.3']),
    )


def test_authorization_runs_custom_strategies() -> None:
    """Authorization retains and can invoke supplied custom strategies."""
    calls: list[tuple[object, object]] = []

    class Strategy:
        def check(self, target: object, policy: object) -> None:
            calls.append((target, policy))

    target = ca()
    policy = object()
    with patch('pki.authorization.SecurityConfig.objects.get', return_value=policy):
        PkiSecurityAuthorization(strategies=[Strategy()]).check(target)

    assert calls == [(target, policy)]
