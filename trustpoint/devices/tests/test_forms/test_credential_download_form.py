"""Test suite for validating the CredentialDownloadForm."""

import pytest

from devices.forms import PASSWORD_MIN_LENGTH, CredentialDownloadForm


@pytest.mark.parametrize(
    ('password', 'expected_errors'),
    [
        # Test Case 1: Valid passwords
        ('validpassword123', {}),
        # Test Case 2: Password too short
        ('short', {'password': [f'Password must be at least {PASSWORD_MIN_LENGTH} characters long.']}),
    ],
)
def test_credential_download_form_clean(password: str, expected_errors: dict[str, list[str]]) -> None:
    """Test the form's validation logic for password matching and length."""
    form_data = {
        'password': password,
    }
    form = CredentialDownloadForm(data=form_data)

    is_valid = form.is_valid()

    if not expected_errors:
        assert is_valid is True, 'Form should be valid with proper data'
    else:
        assert is_valid is False, 'Form should be invalid with invalid data'
        for field, messages in expected_errors.items():
            assert form.errors.get(field) == messages, f'Expected error for {field}: {messages}'


def test_credential_download_form_empty_fields() -> None:
    """Test that the form raises errors when fields are empty."""
    form_data = {
        'password': '',
    }
    form = CredentialDownloadForm(data=form_data)

    is_valid = form.is_valid()

    assert is_valid is False, 'Form should be invalid when fields are empty'
    assert 'password' in form.errors, 'Password field should have errors for being empty'
