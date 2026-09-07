# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for enabling and disabling the auto-generated PKI."""

from __future__ import annotations

from typing import cast

import pytest
from cryptography import x509

from pki.auto_gen_pki import DOMAIN_NAME_PREFIX, UNIQUE_NAME_PREFIX, AutoGenPki
from pki.models import CaModel, DomainModel
from pki.models.certificate import CertificateModel
from pki.util.keys import AutoGenPkiKeyAlgorithm, supported_auto_gen_pki_key_algorithms

pytestmark = pytest.mark.django_db

KEY_ALGORITHM = AutoGenPkiKeyAlgorithm.RSA2048


@pytest.fixture(autouse=True)
def _require_backend_support() -> None:
    """Skip when the active crypto backend cannot generate the test key."""
    if KEY_ALGORITHM not in supported_auto_gen_pki_key_algorithms():
        pytest.skip('Active crypto backend does not support RSA-2048 AutoGenPKI keys.')


class TestAutoGenPkiEnable:
    """Enabling the auto-generated PKI."""

    def test_enabling_creates_root_issuing_ca_and_domain(self) -> None:
        """Enabling builds a root CA, an issuing CA and an active domain."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)

        root_ca = CaModel.objects.get(ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT)
        issuing_ca = AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM)
        domain = DomainModel.objects.get(unique_name=f'{DOMAIN_NAME_PREFIX}_{KEY_ALGORITHM.name}')

        assert issuing_ca is not None
        assert issuing_ca.unique_name.startswith(f'{UNIQUE_NAME_PREFIX}_{KEY_ALGORITHM.name}')
        assert issuing_ca.parent_ca == root_ca
        assert domain.issuing_ca == issuing_ca
        assert domain.is_active is True

    def test_generated_certificates_form_a_valid_ca_chain(self) -> None:
        """The generated issuing CA is a CA signed by the generated root."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        issuing_ca = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))

        issuing_cert = issuing_ca.get_certificate()
        root_cert = cast('CaModel', issuing_ca.parent_ca).get_certificate()

        assert issuing_cert is not None
        assert root_cert is not None
        assert issuing_cert.issuer == root_cert.subject
        assert root_cert.subject == root_cert.issuer
        assert issuing_cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True

    def test_enabling_twice_does_not_create_a_second_issuing_ca(self) -> None:
        """A second enable call is ignored while one is already active."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        first = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))

        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)

        assert CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.AUTOGEN).count() == 1
        assert AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM) == first

    def test_root_ca_is_reused_after_a_disable_enable_cycle(self) -> None:
        """Re-enabling reuses the existing root CA instead of creating a new one."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        original_root = CaModel.objects.get(ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT)
        AutoGenPki.disable_auto_gen_pki()

        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)

        assert CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.AUTOGEN_ROOT).count() == 1
        new_issuing = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))
        assert new_issuing.parent_ca == original_root

    def test_no_pki_is_reported_before_enabling(self) -> None:
        """No auto-generated PKI exists before it is enabled."""
        assert AutoGenPki.get_auto_gen_pki() is None
        assert AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM) is None


class TestAutoGenPkiDisable:
    """Disabling the auto-generated PKI."""

    def test_disabling_deactivates_ca_and_domain(self) -> None:
        """Disabling renames and deactivates the CA and its domain."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        issuing_ca = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))
        original_name = issuing_ca.unique_name

        AutoGenPki.disable_auto_gen_pki()

        issuing_ca.refresh_from_db()
        domain = DomainModel.objects.get(unique_name=f'{DOMAIN_NAME_PREFIX}_{KEY_ALGORITHM.name}')
        assert issuing_ca.is_active is False
        assert issuing_ca.unique_name == f'{original_name}_DISABLED'
        assert domain.is_active is False
        assert AutoGenPki.get_auto_gen_pki() is None

    def test_disabling_revokes_issued_certificates(self) -> None:
        """Certificates issued by the auto-generated PKI are revoked."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        issuing_ca = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))
        issuing_cert_model = cast('CertificateModel', issuing_ca.ca_certificate_model)

        AutoGenPki.disable_auto_gen_pki()

        issuing_cert_model.refresh_from_db()
        assert issuing_cert_model.certificate_status == CertificateModel.CertificateStatus.REVOKED

    def test_disabling_without_active_pki_is_a_no_op(self) -> None:
        """Disabling when nothing is enabled leaves the database untouched."""
        AutoGenPki.disable_auto_gen_pki()

        assert not CaModel.objects.filter(ca_type=CaModel.CaTypeChoice.AUTOGEN).exists()

    def test_disabling_is_idempotent(self) -> None:
        """A second disable call does not rename the CA again."""
        AutoGenPki.enable_auto_gen_pki(key_alg=KEY_ALGORITHM)
        issuing_ca = cast('CaModel', AutoGenPki.get_auto_gen_pki(KEY_ALGORITHM))
        AutoGenPki.disable_auto_gen_pki()
        issuing_ca.refresh_from_db()
        disabled_name = issuing_ca.unique_name

        AutoGenPki.disable_auto_gen_pki()

        issuing_ca.refresh_from_db()
        assert issuing_ca.unique_name == disabled_name
