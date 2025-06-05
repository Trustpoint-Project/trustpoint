import pytest
from devices.forms import BrowserLoginForm
from devices.models import RemoteDeviceCredentialDownloadModel


@pytest.mark.django_db
def test_browser_login_form_valid(remote_device_credential_download):
    """
    Test the BrowserLoginForm with a valid OTP.
    """
    credential_id = remote_device_credential_download.issued_credential_model.pk
    otp = remote_device_credential_download.otp

    full_otp = f"{credential_id}.{otp}"

    form = BrowserLoginForm(data={"otp": full_otp})

    assert form.is_valid(), f"Form errors: {form.errors}"

    cleaned_data = form.cleaned_data
    assert "credential_id" in cleaned_data, "The form should extract 'credential_id' from the OTP."
    assert "credential_download" in cleaned_data, "The form should include the related 'RemoteDeviceCredentialDownloadModel'."
    assert cleaned_data["credential_id"] == credential_id, "The extracted credential ID should match the expected value."
    assert cleaned_data["credential_download"] == remote_device_credential_download, \
        "The extracted credential download instance should match the expected one."


@pytest.mark.django_db
def test_browser_login_form_invalid_otp_structure(remote_device_credential_download):
    """
    Test the BrowserLoginForm with an OTP that has an invalid structure.
    """
    invalid_otp = "invalid_otp"

    form = BrowserLoginForm(data={"otp": invalid_otp})

    assert not form.is_valid(), "The form should be invalid if the OTP structure is incorrect."

    assert "__all__" in form.errors, "A general form-level error should be raised."
    assert form.errors["__all__"][0] == "The provided OTP is invalid.", "Incorrect error message for invalid OTP structure."


@pytest.mark.django_db
def test_browser_login_form_nonexistent_credential(remote_device_credential_download):
    """
    Test the BrowserLoginForm with a non-existent credential ID in the OTP.
    """
    invalid_credential_id = 999999
    otp_value = remote_device_credential_download.otp
    full_otp = f"{invalid_credential_id}.{otp_value}"

    form = BrowserLoginForm(data={"otp": full_otp})

    assert not form.is_valid(), "The form should be invalid if the credential ID does not exist."

    assert "__all__" in form.errors, "A general form-level error should be raised."
    assert form.errors["__all__"][0] == "The credential download process is not valid, it may have expired.", \
        "Incorrect error message for non-existent credential ID."


@pytest.mark.django_db
def test_browser_login_form_invalid_otp_value(remote_device_credential_download):
    """
    Test the BrowserLoginForm with an invalid OTP value.
    """
    credential_id = remote_device_credential_download.issued_credential_model.pk
    invalid_otp_value = "incorrect-otp"
    full_otp = f"{credential_id}.{invalid_otp_value}"

    form = BrowserLoginForm(data={"otp": full_otp})

    assert not form.is_valid(), "The form should be invalid if the OTP value is incorrect."

    assert "__all__" in form.errors, "A general form-level error should be raised."
    assert form.errors["__all__"][0] == "OTP is invalid.", "Incorrect error message for invalid OTP value."


@pytest.mark.django_db
def test_browser_login_form_missing_otp():
    """
    Test the BrowserLoginForm with a missing OTP.
    """
    form = BrowserLoginForm(data={})

    assert not form.is_valid(), "The form should be invalid if no OTP is provided."

    assert "otp" in form.errors, "The 'otp' field should have an error."
    assert form.errors["otp"][0] == "This field is required.", "Incorrect error message for missing OTP."