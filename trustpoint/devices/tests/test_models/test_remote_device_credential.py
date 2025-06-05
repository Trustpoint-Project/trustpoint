from datetime import timedelta

import pytest
from devices.models import RemoteDeviceCredentialDownloadModel

@pytest.mark.django_db
def test_create_remote_device_credential_from_tls_client_credential(tls_client_credential, test_device):
    """
    Test the creation of a RemoteDeviceCredentialDownloadModel instance using the `tls_client_credential` fixture.
    """
    otp_token = "test-otp-token"
    remote_download = RemoteDeviceCredentialDownloadModel.objects.create(
        issued_credential_model=tls_client_credential,
        otp=otp_token,
        device=test_device,
    )

    assert remote_download.issued_credential_model == tls_client_credential, (
        "The issued credential model should match the one used in the creation."
    )
    assert remote_download.device == test_device, (
        "The device should match the one used in the creation."
    )
    assert remote_download.otp == otp_token, (
        "The OTP should match the one used during creation."
    )
    assert remote_download.attempts == 0, "Initial attempts should be 0."
    assert remote_download.download_token == "", "The download token should initially be empty."
    assert remote_download.token_created_at is None, "Token created timestamp should initially be None."

    expected_str = f"RemoteDeviceCredentialDownloadModel(credential={tls_client_credential.id})"
    assert str(remote_download) == expected_str, (
        f"The string representation should be '{expected_str}'."
    )

#  ----------------------------------- save-----------------------------------

@pytest.mark.django_db
def test_save_generates_otp_if_not_set(remote_device_credential_download):
    """Test that `save` generates a new OTP if no OTP is set."""
    remote_device_credential_download.otp = ""
    remote_device_credential_download.save()

    assert remote_device_credential_download.otp != "", "OTP should be generated if it was not set."
    assert isinstance(remote_device_credential_download.otp, str), "Generated OTP should be a string."


@pytest.mark.django_db
def test_save_does_not_modify_existing_otp(remote_device_credential_download):
    """Test that `save` does not modify the OTP if it is already set."""
    existing_otp = remote_device_credential_download.otp

    remote_device_credential_download.save()

    assert remote_device_credential_download.otp == existing_otp, "Existing OTP should not be modified."

#  ----------------------------------- check_token -----------------------------------

@pytest.mark.django_db
def test_check_token_valid(remote_device_credential_download):
    """Test that `check_token` returns True for a valid token within the validity period."""
    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True

    token = remote_device_credential_download.download_token
    assert remote_device_credential_download.check_token(token) is True, \
        "The token should be valid within its validity period."

@pytest.mark.django_db
def test_check_token_missing_token(remote_device_credential_download):
    """
    Test that `check_token` returns False if no token is set.
    """
    assert remote_device_credential_download.download_token == "", (
        "Token should not be set initially."
    )
    assert remote_device_credential_download.check_token("some-token") is False, (
        "`check_token` should return False if no token is set."
    )

@pytest.mark.django_db
def test_check_token_wrong_token(remote_device_credential_download):
    """
    Test that `check_token` returns False for an incorrect token.
    """
    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True

    wrong_token = "wrong-token"
    assert remote_device_credential_download.check_token(wrong_token) is False, (
        "`check_token` should return False for an incorrect token."
    )

@pytest.mark.django_db
def test_check_token_expired(remote_device_credential_download):
    """
    Test that `check_token` returns False for an expired token.
    """
    assert remote_device_credential_download.check_otp(remote_device_credential_download.otp) is True
    token = remote_device_credential_download.download_token

    remote_device_credential_download.token_created_at -= timedelta(
        minutes=RemoteDeviceCredentialDownloadModel.TOKEN_VALIDITY.total_seconds() / 60 + 1
    )
    remote_device_credential_download.save()

    assert remote_device_credential_download.check_token(token) is False, \
        "The token should be invalid after expiration."
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)

#  ----------------------------------- check_otp-----------------------------------

@pytest.mark.django_db
def test_check_otp_valid(remote_device_credential_download):
    """Test that `check_otp` returns True for a valid OTP and invalidates it afterward."""
    otp = remote_device_credential_download.otp

    assert remote_device_credential_download.check_otp(otp) is True, "Valid OTP should return True."

    assert remote_device_credential_download.check_otp(otp) is False, "OTP should not be reusable after a valid attempt."
    assert remote_device_credential_download.otp == "-", "OTP should be marked as invalid after being used."

@pytest.mark.django_db
def test_check_otp_invalid(remote_device_credential_download):
    """Test that `check_otp` returns False for an invalid OTP."""
    invalid_otp = "wrong-otp"

    assert remote_device_credential_download.check_otp(invalid_otp) is False, "Invalid OTP should return False."
    assert remote_device_credential_download.attempts == 1, "Incorrect OTP attempts should update the attempts counter."

@pytest.mark.django_db
def test_check_otp_exceed_max_attempts(remote_device_credential_download):
    """Test that the OTP is invalidated after exceeding the maximum number of allowed attempts."""
    max_attempts = RemoteDeviceCredentialDownloadModel.BROWSER_MAX_OTP_ATTEMPTS
    invalid_otp = "wrong-otp"

    for attempt in range(max_attempts):
        assert remote_device_credential_download.check_otp(invalid_otp) is False, (
            f"Attempt {attempt + 1}: Invalid OTP should return False."
        )

    assert remote_device_credential_download.otp == "-", "OTP should be invalid after exceeding max attempts."
    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)

@pytest.mark.django_db
def test_check_otp_resets_on_max_attempts(remote_device_credential_download):
    """Test that the object is deleted after exceeding max OTP attempts."""
    max_attempts = RemoteDeviceCredentialDownloadModel.BROWSER_MAX_OTP_ATTEMPTS
    invalid_otp = "wrong-otp"

    for _ in range(max_attempts):
        remote_device_credential_download.check_otp(invalid_otp)

    with pytest.raises(RemoteDeviceCredentialDownloadModel.DoesNotExist):
        RemoteDeviceCredentialDownloadModel.objects.get(pk=remote_device_credential_download.pk)

@pytest.mark.django_db
def test_check_otp_creates_download_token(remote_device_credential_download):
    """Test that a valid OTP generates a download token and sets the creation time."""
    otp = remote_device_credential_download.otp

    assert remote_device_credential_download.check_otp(otp) is True, "Valid OTP should return True."

    assert remote_device_credential_download.download_token != "", "A valid OTP should generate a download token."
    assert remote_device_credential_download.token_created_at is not None, "A valid OTP should set the token creation time."

#  ----------------------------------- get_otp_display-----------------------------------

@pytest.mark.django_db
def test_get_otp_display_valid_otp(remote_device_credential_download):
    """
    Test that `get_otp_display` returns the OTP in the correct format when the OTP is valid.
    """
    otp_display = remote_device_credential_download.get_otp_display()
    expected_display = f"{remote_device_credential_download.issued_credential_model.id}.{remote_device_credential_download.otp}"

    assert otp_display == expected_display, (
        f"Expected display format: {expected_display}, got: {otp_display}"
    )

@pytest.mark.django_db
def test_get_otp_display_invalidated_otp(remote_device_credential_download):
    """
    Test that `get_otp_display` returns 'OTP no longer valid' when the OTP is invalidated.
    """
    remote_device_credential_download.otp = "-"
    remote_device_credential_download.save()

    otp_display = remote_device_credential_download.get_otp_display()
    expected_display = "OTP no longer valid"

    assert otp_display == expected_display, (
        f"Expected display: {expected_display}, got: {otp_display}"
    )


