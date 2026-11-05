# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Credential persistence remains independent of certificate profile policy."""

from typing import Any
from unittest.mock import Mock

import pytest

from devices.issuer import CredentialSaver
from pki.models import IssuedCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.tests.credential_helpers import issue_test_credential
from pki.util.keys import KeyGenerator


@pytest.mark.parametrize('external_key', [False, True])
def test_credential_save_errors_propagate(
    device_instance: dict[str, Any],
    *,
    monkeypatch: pytest.MonkeyPatch,
    external_key: bool,
) -> None:
    """Both persistence paths expose failures to the issuance caller."""
    device = device_instance['device']
    key = KeyGenerator.generate_private_key(domain=device.domain) if external_key else None
    method = 'save_keyless_credential' if external_key else 'save_credential_serializer'
    monkeypatch.setattr(
        f'pki.models.credential.CredentialModel.{method}', Mock(side_effect=RuntimeError('Save failed'))
    )
    with pytest.raises(RuntimeError, match='Save failed'):
        issue_test_credential(device, 'tls_client', public_key=key.public_key_serializer.as_crypto() if key else None)


def test_keyless_renewal_reuses_existing_credential(device_instance: dict[str, Any]) -> None:
    """Keyless renewal updates the matching device record rather than creating another one."""
    device = device_instance['device']
    first = issue_test_credential(device, 'domain_credential')
    key = KeyGenerator.generate_private_key(domain=device.domain)
    second = issue_test_credential(device, 'domain_credential', public_key=key.public_key_serializer.as_crypto())
    assert first.pk == second.pk
    assert (
        IssuedCredentialModel.objects.filter(
            device=device,
            issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DOMAIN_CREDENTIAL,
        ).count()
        == 1
    )


def test_credential_saver_preserves_associations_and_updates_profile(device_instance: dict[str, Any]) -> None:
    """Saving a certificate preserves device/domain links and records the selected profile reference."""
    device = device_instance['device']
    issued = issue_test_credential(device, 'tls_client', common_name='saver-test')
    saver = CredentialSaver(device, device.domain)
    assert saver.device == device
    assert saver.domain == device.domain
    profile = CertificateProfileModel.objects.create(unique_name='changed_profile', profile_json={})
    updated = saver.save_keyless_credential(
        issued.credential.get_certificate(),
        issued.credential.get_certificate_chain(),
        'saver-test',
        IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        profile,
    )
    assert updated.pk == issued.pk
    assert updated.certificate_profile == profile
    updated.refresh_from_db()
    assert updated.certificate_profile == profile


def test_remote_credential_creation_and_renewal_store_the_selected_profile(device_instance):
    device = device_instance['device']
    local = issue_test_credential(device, 'tls_client', common_name='remote-test')
    saver = CredentialSaver(device, device.domain)
    certificate = local.credential.get_certificate()
    chain = local.credential.get_certificate_chain()
    first = saver.save_remote_keyless_credential(certificate, chain, 'remote-test', local.certificate_profile)
    assert first.certificate_profile == local.certificate_profile
    replacement = CertificateProfileModel.objects.create(unique_name='replacement_profile', profile_json={})
    renewed = saver.save_remote_keyless_credential(certificate, chain, 'remote-test', replacement)
    assert renewed.pk == first.pk
    renewed.refresh_from_db()
    assert renewed.certificate_profile == replacement
