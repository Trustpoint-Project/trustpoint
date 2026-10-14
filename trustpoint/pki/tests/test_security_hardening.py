# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Regression tests for PKI security hardening."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from trustpoint_core.oid import PublicKeyAlgorithmOid

from management.models import SecurityConfig
from pki.authorization import (
    PkiSecurityAuthorization,
    _NotPermittedEccCurvesStrategy,
    _NotPermittedSignatureAlgorithmsStrategy,
)
from pki.forms.truststores import _validate_chain_integrity, validate_and_create_ca_chain
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateGenerator

pytestmark = pytest.mark.django_db


def _ca(certificate: object | None = None) -> SimpleNamespace:
    """Build a minimal CA-shaped object."""
    return SimpleNamespace(unique_name='test-ca', ca_certificate_model=certificate, crl_validity_hours=24.0)


def _certificate(**values: object) -> SimpleNamespace:
    """Build minimal certificate metadata used by policy strategies."""
    defaults = {
        'spki_algorithm_oid': PublicKeyAlgorithmOid.RSA.dotted_string,
        'spki_ec_curve_oid': '',
        'signature_algorithm_oid': '1.2.840.113549.1.1.11',
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def _config(**values: object) -> SimpleNamespace:
    """Build minimal policy metadata used by policy strategies."""
    defaults = {
        'not_permitted_ecc_curve_oids': [],
        'not_permitted_signature_algorithm_oids': [],
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def test_authorization_rejects_missing_security_config() -> None:
    """Trust-establishing authorization fails closed without a security policy."""
    SecurityConfig.objects.all().delete()

    with pytest.raises(ValueError, match='No SecurityConfig'):
        PkiSecurityAuthorization().check(_ca())  # type: ignore[arg-type]


def test_authorization_rejects_multiple_security_configs() -> None:
    """Ambiguous security-policy state fails closed."""
    SecurityConfig.objects.create(security_mode=SecurityConfig.SecurityModeChoices.LAB)
    SecurityConfig.objects.create(security_mode=SecurityConfig.SecurityModeChoices.BROWNFIELD)

    with pytest.raises(ValueError, match='Multiple SecurityConfig'):
        PkiSecurityAuthorization().check(_ca())  # type: ignore[arg-type]


def test_ecc_policy_rejects_missing_curve_metadata() -> None:
    """ECC certificates cannot bypass policy when their curve metadata is absent."""
    cert = _certificate(
        spki_algorithm_oid=PublicKeyAlgorithmOid.ECC.dotted_string,
        spki_ec_curve_oid='',
    )

    with pytest.raises(ValueError, match='no curve OID'):
        _NotPermittedEccCurvesStrategy().check(_ca(cert), _config())  # type: ignore[arg-type]


def test_signature_policy_rejects_unknown_algorithm_even_without_blocklist() -> None:
    """Unknown signature algorithms fail closed instead of bypassing an empty blocklist."""
    cert = _certificate(signature_algorithm_oid='1.2.3.4.5.6.7.8.9')

    with pytest.raises(ValueError, match='unknown signature algorithm'):
        _NotPermittedSignatureAlgorithmsStrategy().check(_ca(cert), _config())  # type: ignore[arg-type]


def test_chain_integrity_rejects_matching_dn_with_invalid_signature() -> None:
    """Issuer/subject name equality alone cannot establish a CA relationship."""
    legitimate_root, _legitimate_key = CertificateGenerator.create_root_ca('Shared Root')
    _rogue_root, rogue_key = CertificateGenerator.create_root_ca('Shared Root')
    forged_intermediate, _ = CertificateGenerator.create_issuing_ca(
        rogue_key,
        'Shared Root',
        'Forged Intermediate',
    )

    assert forged_intermediate.issuer == legitimate_root.subject
    assert not _validate_chain_integrity([forged_intermediate, legitimate_root])


def test_trust_chain_import_rejects_missing_security_config() -> None:
    """A cryptographically valid chain is not activated without an unambiguous security policy."""
    SecurityConfig.objects.all().delete()
    root, root_key = CertificateGenerator.create_root_ca('Root', path_length=1)
    issuing, _ = CertificateGenerator.create_issuing_ca(root_key, 'Root', 'Issuing', path_length=0)

    with pytest.raises(Exception, match='No SecurityConfig'):
        validate_and_create_ca_chain([issuing, root], TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN)
