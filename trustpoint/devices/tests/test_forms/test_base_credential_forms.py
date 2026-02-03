"""Test suite for Base Credential Forms."""

from typing import Any

import pytest
from django import forms

from devices.forms import BaseCredentialForm, BaseServerCredentialForm
from devices.models import DeviceModel, IssuedCredentialModel


@pytest.mark.django_db
class TestBaseCredentialForm:
    """Tests for BaseCredentialForm."""

    def test_form_initialization_with_device(self, device_instance: dict[str, Any]) -> None:
        """Test that BaseCredentialForm accepts and stores device instance."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert form.device == device
        assert 'common_name' in form.fields
        assert 'validity' in form.fields

    def test_valid_data(self, device_instance: dict[str, Any]) -> None:
        """Test BaseCredentialForm with valid data."""
        device = device_instance['device']
        domain = device_instance['domain']

        # Disabled fields need initial data (they won't be in form_data)
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'test-credential',
            'validity': 365,
        }
        
        form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'
        assert form.cleaned_data['common_name'] == 'test-credential'
        assert form.cleaned_data['validity'] == 365

    def test_clean_common_name_duplicate(
        self, device_instance: dict[str, Any], tls_client_credential_instance: dict[str, Any]
    ) -> None:
        """Test that duplicate common_name raises validation error."""
        device = device_instance['device']
        domain = device_instance['domain']
        issued_cred = tls_client_credential_instance['issued_credential']
        
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': issued_cred.common_name,  # Use existing common_name
            'validity': 365,
        }
        
        form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert not form.is_valid()
        assert 'common_name' in form.errors
        assert 'already exists' in str(form.errors['common_name'][0])

    def test_clean_validity_positive(self, device_instance: dict[str, Any]) -> None:
        """Test that validity must be positive."""
        device = device_instance['device']
        
        form_data = {
            'common_name': 'test-credential',
            'validity': -10,  # Negative validity
        }
        
        form = BaseCredentialForm(data=form_data, device=device)
        
        assert not form.is_valid()
        assert 'validity' in form.errors
        assert 'positive integer' in str(form.errors['validity'][0])

    def test_clean_validity_zero(self, device_instance: dict[str, Any]) -> None:
        """Test that validity cannot be zero."""
        device = device_instance['device']
        
        form_data = {
            'common_name': 'test-credential',
            'validity': 0,  # Zero validity
        }
        
        form = BaseCredentialForm(data=form_data, device=device)
        
        assert not form.is_valid()
        assert 'validity' in form.errors
        assert 'positive integer' in str(form.errors['validity'][0])

    def test_disabled_fields_present(self, device_instance: dict[str, Any]) -> None:
        """Test that disabled fields are present in the form."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert 'pseudonym' in form.fields
        assert 'domain_component' in form.fields
        assert 'serial_number' in form.fields
        assert form.fields['pseudonym'].disabled is True
        assert form.fields['domain_component'].disabled is True
        assert form.fields['serial_number'].disabled is True

    def test_disabled_fields_required(self, device_instance: dict[str, Any]) -> None:
        """Test that disabled fields are marked as required."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert form.fields['pseudonym'].required is True
        assert form.fields['domain_component'].required is True
        assert form.fields['serial_number'].required is True

    def test_form_fields_types(self, device_instance: dict[str, Any]) -> None:
        """Test that form fields are of correct types."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert isinstance(form.fields['common_name'], forms.CharField)
        assert isinstance(form.fields['pseudonym'], forms.CharField)
        assert isinstance(form.fields['domain_component'], forms.CharField)
        assert isinstance(form.fields['serial_number'], forms.CharField)
        assert isinstance(form.fields['validity'], forms.IntegerField)

    def test_common_name_max_length(self, device_instance: dict[str, Any]) -> None:
        """Test common_name field max_length."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert form.fields['common_name'].max_length == 255

    def test_validity_initial_value(self, device_instance: dict[str, Any]) -> None:
        """Test that validity has an initial value."""
        device = device_instance['device']
        
        form = BaseCredentialForm(device=device)
        
        assert form.fields['validity'].initial == 10

    def test_very_long_common_name(self, device_instance: dict[str, Any]) -> None:
        """Test validation with a very long common_name."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        # Create a common_name that exceeds 255 characters
        long_name = 'a' * 256
        
        form_data = {
            'common_name': long_name,
            'validity': 365,
        }
        
        form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert not form.is_valid()
        assert 'common_name' in form.errors

    def test_large_validity_value(self, device_instance: dict[str, Any]) -> None:
        """Test form with a very large validity value."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'test-credential',
            'validity': 9999,  # Very large validity
        }
        
        form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should accept large validity values, errors: {form.errors}'
        assert form.cleaned_data['validity'] == 9999

    def test_invalid_common_name_characters(self, device_instance: dict[str, Any]) -> None:
        """Test that common names with invalid characters are rejected."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        invalid_names = [
            'device@example.com',
            'device.com/path',
            'http://evil.com',
        ]
        
        for invalid_name in invalid_names:
            form_data = {
                'common_name': invalid_name,
                'validity': 365,
            }
            
            form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
            
            assert not form.is_valid(), f'Form should reject invalid common name: {invalid_name}'
            assert 'common_name' in form.errors
            assert 'can only contain' in str(form.errors['common_name'][0]).lower()

    def test_url_like_common_name(self, device_instance: dict[str, Any]) -> None:
        """Test that URL-like common names are rejected."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'test-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        url_like_names = [
            'https://evil.com',
            'ftp://test.com',
            'device.com:8080',
        ]
        
        for url_name in url_like_names:
            form_data = {
                'common_name': url_name,
                'validity': 365,
            }
            
            form = BaseCredentialForm(data=form_data, initial=initial_data, device=device)
            
            assert not form.is_valid(), f'Form should reject URL-like common name: {url_name}'
            assert 'common_name' in form.errors
            assert 'url-like' in str(form.errors['common_name'][0]).lower()


@pytest.mark.django_db
class TestBaseServerCredentialForm:
    """Tests for BaseServerCredentialForm."""

    def test_form_has_server_fields(self, device_instance: dict[str, Any]) -> None:
        """Test that BaseServerCredentialForm has additional server fields."""
        device = device_instance['device']
        
        form = BaseServerCredentialForm(device=device)
        
        assert 'ipv4_addresses' in form.fields
        assert 'ipv6_addresses' in form.fields
        assert 'domain_names' in form.fields

    def test_valid_ipv4_addresses(self, device_instance: dict[str, Any]) -> None:
        """Test validation of valid IPv4 addresses."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '192.168.1.1, 10.0.0.1',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 2

    def test_invalid_ipv4_addresses(self, device_instance: dict[str, Any]) -> None:
        """Test validation of invalid IPv4 addresses."""
        device = device_instance['device']
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '999.999.999.999, not-an-ip',  # Invalid IPs
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, device=device)
        
        assert not form.is_valid()
        assert 'ipv4_addresses' in form.errors

    def test_valid_ipv6_addresses(self, device_instance: dict[str, Any]) -> None:
        """Test validation of valid IPv6 addresses."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '::1, 2001:db8::1',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'
        ipv6_list = form.cleaned_data['ipv6_addresses']
        assert len(ipv6_list) == 2

    def test_invalid_ipv6_addresses(self, device_instance: dict[str, Any]) -> None:
        """Test validation of invalid IPv6 addresses."""
        device = device_instance['device']
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': 'not-a-valid-ipv6, gggg::1',  # Invalid IPv6
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, device=device)
        
        assert not form.is_valid()
        assert 'ipv6_addresses' in form.errors

    def test_valid_domain_names(self, device_instance: dict[str, Any]) -> None:
        """Test validation of valid domain names."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': 'example.com, sub.example.org',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid, errors: {form.errors}'
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 2
        assert 'example.com' in domain_list
        assert 'sub.example.org' in domain_list

    def test_empty_server_fields(self, device_instance: dict[str, Any]) -> None:
        """Test form validation when all server fields are empty - requires at least one SAN."""
        device = device_instance['device']
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, device=device)
        
        # Based on the form validation, at least one SAN entry is required
        # So this should be invalid
        assert not form.is_valid(), 'Form should be invalid when all server fields are empty'

    def test_mixed_san_entries(self, device_instance: dict[str, Any]) -> None:
        """Test form with multiple types of SAN entries."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'mixed-server-credential',
            'validity': 180,
            'ipv4_addresses': '192.168.1.1, 10.0.0.1',
            'ipv6_addresses': '::1, 2001:db8::1',
            'domain_names': 'example.com, test.example.com',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid with mixed SAN entries, errors: {form.errors}'
        assert len(form.cleaned_data['ipv4_addresses']) == 2
        assert len(form.cleaned_data['ipv6_addresses']) == 2
        assert len(form.cleaned_data['domain_names']) == 2

    def test_ipv4_with_trailing_spaces(self, device_instance: dict[str, Any]) -> None:
        """Test that IPv4 addresses with trailing spaces are handled correctly."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '192.168.1.1 ,  10.0.0.1  ',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should handle spaces in IPv4 addresses, errors: {form.errors}'
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 2

    def test_ipv6_with_trailing_spaces(self, device_instance: dict[str, Any]) -> None:
        """Test that IPv6 addresses with trailing spaces are handled correctly."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': ' ::1 , 2001:db8::1 ',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should handle spaces in IPv6 addresses, errors: {form.errors}'
        ipv6_list = form.cleaned_data['ipv6_addresses']
        assert len(ipv6_list) == 2

    def test_domain_names_with_trailing_spaces(self, device_instance: dict[str, Any]) -> None:
        """Test that domain names with trailing spaces are handled correctly."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': ' example.com , test.example.com ',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should handle spaces in domain names, errors: {form.errors}'
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 2
        assert 'example.com' in domain_list
        assert 'test.example.com' in domain_list

    def test_empty_entries_in_comma_separated_list(self, device_instance: dict[str, Any]) -> None:
        """Test that empty entries in comma-separated lists are ignored."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '192.168.1.1, , 10.0.0.1',  # Empty entry in middle
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should ignore empty entries, errors: {form.errors}'
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 2  # Empty entry should be filtered out

    def test_single_ipv4_address(self, device_instance: dict[str, Any]) -> None:
        """Test form with a single IPv4 address."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '192.168.1.1',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should be valid with single IPv4, errors: {form.errors}'
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 1

    def test_localhost_ipv4(self, device_instance: dict[str, Any]) -> None:
        """Test form with localhost IPv4 address."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '127.0.0.1',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should accept localhost IPv4, errors: {form.errors}'

    def test_localhost_ipv6(self, device_instance: dict[str, Any]) -> None:
        """Test form with localhost IPv6 address."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '::1',
            'domain_names': '',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should accept localhost IPv6, errors: {form.errors}'

    def test_subdomain_with_multiple_levels(self, device_instance: dict[str, Any]) -> None:
        """Test form with multi-level subdomain names."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        form_data = {
            'common_name': 'server-credential',
            'validity': 180,
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': 'api.v1.prod.example.com, web.staging.example.com',
        }
        
        form = BaseServerCredentialForm(data=form_data, initial=initial_data, device=device)
        
        assert form.is_valid(), f'Form should accept multi-level subdomains, errors: {form.errors}'
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 2
