"""Test cases for Remote Device Credential Download."""

import datetime
import secrets
from typing import Any

import pytest

from devices.models import RemoteDeviceCredentialDownloadModel


def test_otp_generation(mock_models: dict[str, Any]) -> None:
    """Test that a valid OTP is generated on save."""
    remote_credential_download_model = mock_models['remote_credential_download']
    assert remote_credential_download_model.otp == ''
    remote_credential_download_model.save()
    assert len(remote_credential_download_model.otp) == len(secrets.token_urlsafe(8))


def test_token_invalidation(mock_models: dict[str, Any]) -> None:
    """Test that a download token is no longer valid after the token validity period."""
    rcd = mock_models['remote_credential_download']
    # no token present at initialization
    rcd.save()
    assert rcd.download_token == ''
    assert rcd.check_otp(rcd.otp)
    assert rcd.download_token != ''
    assert rcd.check_token(rcd.download_token)
    rcd.token_created_at = rcd.token_created_at - rcd.TOKEN_VALIDITY - datetime.timedelta(minutes=1)
    assert not rcd.check_token(rcd.download_token)
    # ensure model was deleted
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(id=rcd.id)


def test_otp_use_once(mock_models: dict[str, Any]) -> None:
    """Test that an OTP can only be used once."""
    rcd = mock_models['remote_credential_download']
    rcd.save()
    otp = rcd.otp
    assert rcd.check_otp(otp)
    assert not rcd.check_otp(otp)
    assert len(rcd.otp) < 2  # noqa: PLR2004


def test_otp_max_attempts(mock_models: dict[str, Any]) -> None:
    """Test that the OTP is invalidated after too many incorrect attempts."""
    rcd = mock_models['remote_credential_download']
    rcd.save()
    valid_otp = rcd.otp
    for _ in range(rcd.BROWSER_MAX_OTP_ATTEMPTS):
        assert not rcd.check_otp('invalid_otp')

    assert not rcd.check_otp(valid_otp)

    # ensure model was deleted
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(id=rcd.id)
