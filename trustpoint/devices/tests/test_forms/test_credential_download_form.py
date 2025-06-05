import pytest
from devices.forms import CredentialDownloadForm, PASSWORD_MIN_LENGTH


@pytest.mark.parametrize(
    "password, confirm_password, expected_errors",
    [
        # Test Case 1: Valid passwords
        ("validpassword123", "validpassword123", {}),

        # Test Case 2: Passwords do not match
        ("password123", "differentpassword123", {"confirm_password": ["Passwords do not match."]}),

        # Test Case 3: Password too short
        ("short", "short", {"password": [f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."]}),

        # Test Case 4: Password too short and mismatched
        ("short", "different", {
            "password": [f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."],
            "confirm_password": ["Passwords do not match."]
        }),
    ]
)
def test_credential_download_form_clean(password, confirm_password, expected_errors):
    """Test the form's validation logic for password matching and length."""
    form_data = {
        "password": password,
        "confirm_password": confirm_password,
    }
    form = CredentialDownloadForm(data=form_data)

    is_valid = form.is_valid()

    if not expected_errors:
        assert is_valid is True, "Form should be valid with proper data"
    else:
        assert is_valid is False, "Form should be invalid with invalid data"
        for field, messages in expected_errors.items():
            assert form.errors.get(field) == messages, f"Expected error for {field}: {messages}"


def test_credential_download_form_empty_fields():
    """Test that the form raises errors when fields are empty."""
    form_data = {
        "password": "",
        "confirm_password": "",
    }
    form = CredentialDownloadForm(data=form_data)

    is_valid = form.is_valid()

    assert is_valid is False, "Form should be invalid when fields are empty"
    assert "password" in form.errors, "Password field should have errors for being empty"
    assert "confirm_password" in form.errors, "Confirm password field should have errors for being empty"
