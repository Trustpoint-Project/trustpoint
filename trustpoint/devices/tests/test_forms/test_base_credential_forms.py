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
