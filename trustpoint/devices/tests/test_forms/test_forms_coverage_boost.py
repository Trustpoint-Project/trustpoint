"""Additional tests for forms to improve coverage."""

from typing import Any

import pytest

from devices.forms import CredentialDownloadForm, BrowserLoginForm
from devices.models import RemoteDeviceCredentialDownloadModel


@pytest.mark.django_db
class TestCredentialDownloadFormPasswordValidation:
    """Extended tests for CredentialDownloadForm password validation."""

    def test_missing_password(self) -> None:
        """Test that missing password triggers validation error."""
        form_data = {
            'password': '',
            'password_confirm': '',
        }

        form = CredentialDownloadForm(data=form_data)

        assert not form.is_valid()
        assert 'password' in form.errors
        assert 'required' in str(form.errors['password'][0]).lower()

    def test_password_exactly_min_length(self) -> None:
        """Test password with exactly minimum length."""
        # PASSWORD_MIN_LENGTH is 12
        form_data = {
            'password': '123456789012',  # Exactly 12 characters
            'password_confirm': '123456789012',
        }

        form = CredentialDownloadForm(data=form_data)

        assert form.is_valid(), f'Password of exactly min length should be valid, errors: {form.errors}'

    def test_password_one_char_below_min(self) -> None:
        """Test password one character below minimum length."""
        form_data = {
            'password': '12345678901',  # 11 characters (below min of 12)
            'password_confirm': '12345678901',
        }

        form = CredentialDownloadForm(data=form_data)

        assert not form.is_valid()
        assert 'password' in form.errors
        assert 'at least' in str(form.errors['password'][0])


@pytest.mark.django_db
class TestBrowserLoginFormExtended:
    """Extended tests for BrowserLoginForm to cover uncovered lines."""

    def test_empty_otp_field(self) -> None:
        """Test form with completely empty OTP field."""
        form_data = {
            'otp': '',
        }

        form = BrowserLoginForm(data=form_data)

        assert not form.is_valid()
        assert 'otp' in form.errors

    def test_otp_wrong_number_of_parts(self) -> None:
        """Test OTP with wrong number of dot-separated parts."""
        form_data = {
            'otp': '123',  # Missing the dot separator
        }

        form = BrowserLoginForm(data=form_data)

        assert not form.is_valid()
        assert 'invalid' in str(form.errors['__all__'][0]).lower()

    def test_otp_non_numeric_credential_id(self) -> None:
        """Test OTP with non-numeric credential ID part."""
        form_data = {
            'otp': 'abc.validotppart',  # Non-numeric ID
        }

        form = BrowserLoginForm(data=form_data)

        assert not form.is_valid()
        assert 'invalid' in str(form.errors['__all__'][0]).lower()

    def test_otp_credential_not_found(self, tls_client_credential_instance: dict[str, Any]) -> None:
        """Test OTP referencing non-existent credential ID."""
        # Use a credential ID that definitely doesn't exist
        non_existent_id = 99999

        form_data = {
            'otp': f'{non_existent_id}.someotp',
        }

        form = BrowserLoginForm(data=form_data)

        assert not form.is_valid()
        # Should get error about credential download not being valid or expired
        errors_str = str(form.errors['__all__'][0]).lower()
        assert 'not valid' in errors_str or 'expired' in errors_str

    def test_otp_invalid_hash(
        self, tls_client_credential_instance: dict[str, Any], device_instance: dict[str, Any]
    ) -> None:
        """Test OTP with valid structure but invalid OTP hash."""
        issued_credential = tls_client_credential_instance['issued_credential']
        device = device_instance['device']

        # Create a RemoteDeviceCredentialDownloadModel for this credential
        download_model = RemoteDeviceCredentialDownloadModel.objects.create(
            issued_credential_model=issued_credential, device=device
        )

        form_data = {
            'otp': f'{issued_credential.pk}.wrongotphash',  # Wrong OTP value
        }

        form = BrowserLoginForm(data=form_data)

        assert not form.is_valid()
        assert 'invalid' in str(form.errors['__all__'][0]).lower()


@pytest.mark.django_db
class TestOnboardingCreateFormExceptionHandling:
    """Test exception handling in OnboardingCreateForm."""

    def test_invalid_onboarding_protocol_value(self, device_instance: dict[str, Any]) -> None:
        """Test form with invalid onboarding protocol value."""
        domain = device_instance['domain']

        # Import OnboardingPkiProtocol for the correct enum
        from onboarding.models import OnboardingPkiProtocol
        
        form_data = {
            'common_name': 'test-invalid-protocol',
            'serial_number': 'SN999999',
            'domain': domain.pk,
            'onboarding_protocol': 'invalid_value',  # Invalid protocol
            'onboarding_pki_protocols': [str(OnboardingPkiProtocol.CMP.value)],
        }

        from devices.forms import OnboardingCreateForm

        form = OnboardingCreateForm(data=form_data)

        # Should fail validation due to invalid choice
        assert not form.is_valid()
        assert 'onboarding_protocol' in form.errors
