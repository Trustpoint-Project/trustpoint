# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Credential persistence remains independent of certificate profile policy."""

from typing import Any
from unittest.mock import Mock

import pytest

from devices.issuer import CredentialSaver
from pki.models import IssuedCredentialModel
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


def test_credential_saver_preserves_associations_and_profile_label(device_instance: dict[str, Any]) -> None:
    """Saving a certificate preserves device/domain links and records the selected profile label."""
    device = device_instance['device']
    issued = issue_test_credential(device, 'tls_client', common_name='saver-test')
    saver = CredentialSaver(device, device.domain)
    assert saver.device == device
    assert saver.domain == device.domain
    updated = saver.save_keyless_credential(
        issued.credential.get_certificate(),
        issued.credential.get_certificate_chain(),
        'saver-test',
        IssuedCredentialModel.IssuedCredentialType.APPLICATION_CREDENTIAL,
        'Changed Profile Label',
    )
    assert updated.pk == issued.pk
    assert updated.issued_using_cert_profile == 'Changed Profile Label'
