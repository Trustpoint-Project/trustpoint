"""Tests for credential forms that extend BaseCredentialForm."""

from typing import Any

import pytest

from devices.forms import (
    IssueDomainCredentialForm,
    IssueTlsClientCredentialForm,
    IssueTlsServerCredentialForm,
    IssueOpcUaClientCredentialForm,
    IssueOpcUaServerCredentialForm,
)


@pytest.mark.django_db
class TestIssueDomainCredentialForm:
    """Tests for IssueDomainCredentialForm."""

    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test that IssueDomainCredentialForm initializes with disabled common_name field."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'domain-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form = IssueDomainCredentialForm(initial=initial_data, device=device)

        assert 'common_name' in form.fields
        assert form.fields['common_name'].disabled is True
        assert form.fields['common_name'].initial == 'Trustpoint Domain Credential'

    def test_form_with_custom_common_name_disabled(self, device_instance: dict[str, Any]) -> None:
        """Test that common_name is disabled and uses initial value."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'domain-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        # Try to override the common_name (should be ignored due to disabled=True)
        form_data = {
            'common_name': 'Custom Name',  # This should be ignored
            'validity': 365,
        }

        form = IssueDomainCredentialForm(data=form_data, initial=initial_data, device=device)

        # The form should use the initial value, not the data value
        assert form.is_valid()


@pytest.mark.django_db
class TestIssueTlsClientCredentialForm:
    """Tests for IssueTlsClientCredentialForm."""

    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test IssueTlsClientCredentialForm initialization."""
        device = device_instance['device']

        form = IssueTlsClientCredentialForm(device=device)

        assert 'common_name' in form.fields
        assert 'validity' in form.fields
        assert 'pseudonym' in form.fields
        assert 'domain_component' in form.fields
        assert 'serial_number' in form.fields

    def test_valid_form_submission(self, device_instance: dict[str, Any]) -> None:
        """Test valid TLS client credential form submission."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'tls-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'tls-client-cert',
            'validity': 365,
        }

        form = IssueTlsClientCredentialForm(data=form_data, initial=initial_data, device=device)

        assert form.is_valid()
        assert form.cleaned_data['common_name'] == 'tls-client-cert'
        assert form.cleaned_data['validity'] == 365


@pytest.mark.django_db
class TestIssueTlsServerCredentialForm:
    """Tests for IssueTlsServerCredentialForm."""

    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test IssueTlsServerCredentialForm initialization."""
        device = device_instance['device']

        form = IssueTlsServerCredentialForm(device=device)

        assert 'common_name' in form.fields
        assert 'validity' in form.fields
        assert 'ipv4_addresses' in form.fields
        assert 'ipv6_addresses' in form.fields
        assert 'domain_names' in form.fields

    def test_valid_form_with_san_entries(self, device_instance: dict[str, Any]) -> None:
        """Test valid TLS server credential form with SAN entries."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'tls-server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'tls-server-cert',
            'validity': 365,
            'ipv4_addresses': '192.168.1.1',
            'ipv6_addresses': '',
            'domain_names': 'example.com',
        }

        form = IssueTlsServerCredentialForm(data=form_data, initial=initial_data, device=device)

        assert form.is_valid()
        assert form.cleaned_data['common_name'] == 'tls-server-cert'


@pytest.mark.django_db
class TestApplicationUriFormMixin:
    """Tests for ApplicationUriFormMixin."""

    def test_clean_application_uri_valid(self, device_instance: dict[str, Any]) -> None:
        """Test that valid application URI is accepted."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-client-cert',
            'validity': 365,
            'application_uri': 'urn:example:app',
        }

        form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)

        assert form.is_valid()
        assert form.cleaned_data['application_uri'] == 'urn:example:app'

    def test_clean_application_uri_empty(self, device_instance: dict[str, Any]) -> None:
        """Test that empty application URI is rejected."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-client-cert',
            'validity': 365,
            'application_uri': '',  # Empty URI
        }

        form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)

        assert not form.is_valid()
        assert 'application_uri' in form.errors
        assert 'required' in str(form.errors['application_uri'][0])

    def test_clean_application_uri_whitespace_only(self, device_instance: dict[str, Any]) -> None:
        """Test that whitespace-only application URI is rejected."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-client-cert',
            'validity': 365,
            'application_uri': '   ',  # Whitespace only
        }

        form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)

        assert not form.is_valid()
        assert 'application_uri' in form.errors

    def test_clean_application_uri_http_https_rejected(self, device_instance: dict[str, Any]) -> None:
        """Test that HTTP and HTTPS application URIs are rejected."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        invalid_uris = [
            'http://example.com/app',
            'https://secure.example.com/api',
        ]
        
        for invalid_uri in invalid_uris:
            form_data = {
                'common_name': 'opcua-client-cert',
                'validity': 365,
                'application_uri': invalid_uri,
            }
            
            form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)
            
            assert not form.is_valid(), f'Form should reject HTTP/HTTPS URI: {invalid_uri}'
            assert 'application_uri' in form.errors
            assert 'not allowed' in str(form.errors['application_uri'][0]).lower()

    def test_clean_application_uri_invalid_scheme(self, device_instance: dict[str, Any]) -> None:
        """Test that application URIs without valid schemes are rejected."""
        device = device_instance['device']
        domain = device_instance['domain']
        
        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }
        
        invalid_uris = [
            'invalid-uri',
            'no-scheme',
            'urn:',  # Incomplete URN
        ]
        
        for invalid_uri in invalid_uris:
            form_data = {
                'common_name': 'opcua-client-cert',
                'validity': 365,
                'application_uri': invalid_uri,
            }
            
            form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)
            
            assert not form.is_valid(), f'Form should reject invalid URI: {invalid_uri}'
            assert 'application_uri' in form.errors


@pytest.mark.django_db
class TestIssueOpcUaClientCredentialForm:
    """Tests for IssueOpcUaClientCredentialForm."""

    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test IssueOpcUaClientCredentialForm initialization."""
        device = device_instance['device']

        form = IssueOpcUaClientCredentialForm(device=device)

        assert 'common_name' in form.fields
        assert 'validity' in form.fields
        assert 'application_uri' in form.fields

    def test_valid_form_submission(self, device_instance: dict[str, Any]) -> None:
        """Test valid OPC UA client credential form submission."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-client-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-client-cert',
            'validity': 365,
            'application_uri': 'urn:example:app:client',
        }

        form = IssueOpcUaClientCredentialForm(data=form_data, initial=initial_data, device=device)

        assert form.is_valid()
        assert form.cleaned_data['common_name'] == 'opcua-client-cert'
        assert form.cleaned_data['application_uri'] == 'urn:example:app:client'


@pytest.mark.django_db
class TestIssueOpcUaServerCredentialForm:
    """Tests for IssueOpcUaServerCredentialForm."""

    def test_form_initialization(self, device_instance: dict[str, Any]) -> None:
        """Test IssueOpcUaServerCredentialForm initialization."""
        device = device_instance['device']

        form = IssueOpcUaServerCredentialForm(device=device)

        assert 'common_name' in form.fields
        assert 'validity' in form.fields
        assert 'application_uri' in form.fields
        assert 'ipv4_addresses' in form.fields
        assert 'ipv6_addresses' in form.fields
        assert 'domain_names' in form.fields

    def test_valid_form_with_san_and_application_uri(self, device_instance: dict[str, Any]) -> None:
        """Test valid OPC UA server credential form with SAN entries and application URI."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-server-cert',
            'validity': 365,
            'application_uri': 'urn:example:app:server',
            'ipv4_addresses': '192.168.1.10',
            'ipv6_addresses': '',
            'domain_names': 'opcua.example.com',
        }

        form = IssueOpcUaServerCredentialForm(data=form_data, initial=initial_data, device=device)

        assert form.is_valid()
        assert form.cleaned_data['common_name'] == 'opcua-server-cert'
        assert form.cleaned_data['application_uri'] == 'urn:example:app:server'

    def test_invalid_form_without_san(self, device_instance: dict[str, Any]) -> None:
        """Test that OPC UA server form requires at least one SAN entry."""
        device = device_instance['device']
        domain = device_instance['domain']

        initial_data = {
            'pseudonym': 'opcua-server-pseudonym',
            'domain_component': domain.unique_name,
            'serial_number': device.serial_number,
        }

        form_data = {
            'common_name': 'opcua-server-cert',
            'validity': 365,
            'application_uri': 'urn:example:app:server',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }

        form = IssueOpcUaServerCredentialForm(data=form_data, initial=initial_data, device=device)

        assert not form.is_valid()
        # Should fail due to missing SAN entries
