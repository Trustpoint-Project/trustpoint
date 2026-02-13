"""Tests for StartupWizardTlsCertificateForm."""

import ipaddress

import pytest
from django.core.exceptions import ValidationError

from setup_wizard.forms import StartupWizardTlsCertificateForm


class TestStartupWizardTlsCertificateForm:
    """Test cases for StartupWizardTlsCertificateForm."""

    def test_form_has_expected_fields(self):
        """Test form has the expected fields."""
        form = StartupWizardTlsCertificateForm()
        assert 'ipv4_addresses' in form.fields
        assert 'ipv6_addresses' in form.fields
        assert 'domain_names' in form.fields

    def test_form_field_defaults(self):
        """Test form fields have correct default values."""
        form = StartupWizardTlsCertificateForm()
        assert form.fields['ipv4_addresses'].initial == '127.0.0.1, '
        assert form.fields['ipv6_addresses'].initial == '::1, '
        assert form.fields['domain_names'].initial == 'localhost, '
        assert form.fields['ipv4_addresses'].required is False
        assert form.fields['ipv6_addresses'].required is False
        assert form.fields['domain_names'].required is False

    def test_clean_ipv4_addresses_valid_single(self):
        """Test cleaning a single valid IPv4 address."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '192.168.1.1', 'ipv6_addresses': '', 'domain_names': 'example.com'}
        )
        assert form.is_valid()
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 1
        assert ipv4_list[0] == ipaddress.IPv4Address('192.168.1.1')

    def test_clean_ipv4_addresses_valid_multiple(self):
        """Test cleaning multiple valid IPv4 addresses."""
        form = StartupWizardTlsCertificateForm(
            data={
                'ipv4_addresses': '192.168.1.1, 10.0.0.1, 172.16.0.1',
                'ipv6_addresses': '',
                'domain_names': 'example.com',
            }
        )
        assert form.is_valid()
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 3
        assert ipv4_list[0] == ipaddress.IPv4Address('192.168.1.1')
        assert ipv4_list[1] == ipaddress.IPv4Address('10.0.0.1')
        assert ipv4_list[2] == ipaddress.IPv4Address('172.16.0.1')

    def test_clean_ipv4_addresses_empty_string(self):
        """Test cleaning empty IPv4 addresses returns empty list."""
        form = StartupWizardTlsCertificateForm(data={'ipv4_addresses': '', 'ipv6_addresses': '::1', 'domain_names': ''})
        assert form.is_valid()
        assert form.cleaned_data['ipv4_addresses'] == []

    def test_clean_ipv4_addresses_whitespace_only(self):
        """Test cleaning whitespace-only IPv4 addresses returns empty list."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '   ', 'ipv6_addresses': '::1', 'domain_names': ''}
        )
        assert form.is_valid()
        assert form.cleaned_data['ipv4_addresses'] == []

    def test_clean_ipv4_addresses_with_trailing_comma(self):
        """Test cleaning IPv4 addresses with trailing comma."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '192.168.1.1, ', 'ipv6_addresses': '', 'domain_names': 'example.com'}
        )
        assert form.is_valid()
        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 1
        assert ipv4_list[0] == ipaddress.IPv4Address('192.168.1.1')

    def test_clean_ipv4_addresses_invalid(self):
        """Test cleaning invalid IPv4 address raises ValidationError."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '999.999.999.999', 'ipv6_addresses': '', 'domain_names': 'example.com'}
        )
        assert not form.is_valid()
        assert 'ipv4_addresses' in form.errors
        assert 'invalid IPv4-Address' in str(form.errors['ipv4_addresses'])

    def test_clean_ipv4_addresses_mixed_valid_invalid(self):
        """Test cleaning mixed valid and invalid IPv4 addresses."""
        form = StartupWizardTlsCertificateForm(
            data={
                'ipv4_addresses': '192.168.1.1, invalid, 10.0.0.1',
                'ipv6_addresses': '',
                'domain_names': 'example.com',
            }
        )
        assert not form.is_valid()
        assert 'ipv4_addresses' in form.errors

    def test_clean_ipv6_addresses_valid_single(self):
        """Test cleaning a single valid IPv6 address."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '', 'ipv6_addresses': '2001:db8::1', 'domain_names': 'example.com'}
        )
        assert form.is_valid()
        ipv6_list = form.cleaned_data['ipv6_addresses']
        assert len(ipv6_list) == 1
        assert ipv6_list[0] == ipaddress.IPv6Address('2001:db8::1')

    def test_clean_ipv6_addresses_valid_multiple(self):
        """Test cleaning multiple valid IPv6 addresses."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '', 'ipv6_addresses': '2001:db8::1, fe80::1, ::1', 'domain_names': 'example.com'}
        )
        assert form.is_valid()
        ipv6_list = form.cleaned_data['ipv6_addresses']
        assert len(ipv6_list) == 3
        assert ipv6_list[0] == ipaddress.IPv6Address('2001:db8::1')
        assert ipv6_list[1] == ipaddress.IPv6Address('fe80::1')
        assert ipv6_list[2] == ipaddress.IPv6Address('::1')

    def test_clean_ipv6_addresses_empty_string(self):
        """Test cleaning empty IPv6 addresses returns empty list."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '127.0.0.1', 'ipv6_addresses': '', 'domain_names': ''}
        )
        assert form.is_valid()
        assert form.cleaned_data['ipv6_addresses'] == []

    def test_clean_ipv6_addresses_whitespace_only(self):
        """Test cleaning whitespace-only IPv6 addresses returns empty list."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '127.0.0.1', 'ipv6_addresses': '   ', 'domain_names': ''}
        )
        assert form.is_valid()
        assert form.cleaned_data['ipv6_addresses'] == []

    def test_clean_ipv6_addresses_invalid(self):
        """Test cleaning invalid IPv6 address raises ValidationError."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '', 'ipv6_addresses': 'not:valid:ipv6', 'domain_names': 'example.com'}
        )
        assert not form.is_valid()
        assert 'ipv6_addresses' in form.errors
        assert 'invalid IPv6-Address' in str(form.errors['ipv6_addresses'])

    def test_clean_domain_names_valid_single(self):
        """Test cleaning a single domain name."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '127.0.0.1', 'ipv6_addresses': '', 'domain_names': 'example.com'}
        )
        assert form.is_valid()
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 1
        assert domain_list[0] == 'example.com'

    def test_clean_domain_names_valid_multiple(self):
        """Test cleaning multiple domain names."""
        form = StartupWizardTlsCertificateForm(
            data={
                'ipv4_addresses': '',
                'ipv6_addresses': '',
                'domain_names': 'example.com, www.example.com, api.example.com',
            }
        )
        assert form.is_valid()
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 3
        assert 'example.com' in domain_list
        assert 'www.example.com' in domain_list
        assert 'api.example.com' in domain_list

    def test_clean_domain_names_empty_string(self):
        """Test cleaning empty domain names returns empty list."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '127.0.0.1', 'ipv6_addresses': '', 'domain_names': ''}
        )
        assert form.is_valid()
        assert form.cleaned_data['domain_names'] == []

    def test_clean_domain_names_whitespace_only(self):
        """Test cleaning whitespace-only domain names returns empty list."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '127.0.0.1', 'ipv6_addresses': '', 'domain_names': '   '}
        )
        assert form.is_valid()
        assert form.cleaned_data['domain_names'] == []

    def test_clean_domain_names_with_trailing_comma(self):
        """Test cleaning domain names with trailing comma."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '', 'ipv6_addresses': '', 'domain_names': 'example.com, '}
        )
        assert form.is_valid()
        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 1
        assert domain_list[0] == 'example.com'

    def test_clean_all_san_types_provided(self):
        """Test form validation with all SAN types provided."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '192.168.1.1', 'ipv6_addresses': '2001:db8::1', 'domain_names': 'example.com'}
        )
        assert form.is_valid()

    def test_clean_no_san_entries_raises_error(self):
        """Test form validation fails when no SAN entries provided."""
        form = StartupWizardTlsCertificateForm(data={'ipv4_addresses': '', 'ipv6_addresses': '', 'domain_names': ''})
        assert not form.is_valid()
        assert '__all__' in form.errors
        assert 'At least one SAN entry is required' in str(form.errors['__all__'])

    def test_clean_only_ipv4(self):
        """Test form validation with only IPv4 addresses."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '192.168.1.1', 'ipv6_addresses': '', 'domain_names': ''}
        )
        assert form.is_valid()

    def test_clean_only_ipv6(self):
        """Test form validation with only IPv6 addresses."""
        form = StartupWizardTlsCertificateForm(data={'ipv4_addresses': '', 'ipv6_addresses': '::1', 'domain_names': ''})
        assert form.is_valid()

    def test_clean_only_domain_names(self):
        """Test form validation with only domain names."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '', 'ipv6_addresses': '', 'domain_names': 'localhost'}
        )
        assert form.is_valid()

    def test_clean_whitespace_not_counted_as_san_entry(self):
        """Test form validation treats whitespace-only fields as empty."""
        form = StartupWizardTlsCertificateForm(
            data={'ipv4_addresses': '   ', 'ipv6_addresses': '  ', 'domain_names': '  '}
        )
        assert not form.is_valid()
        assert '__all__' in form.errors

    def test_clean_with_extra_whitespace_in_addresses(self):
        """Test cleaning handles extra whitespace in addresses."""
        form = StartupWizardTlsCertificateForm(
            data={
                'ipv4_addresses': '  192.168.1.1  ,  10.0.0.1  ',
                'ipv6_addresses': '  ::1  ,  2001:db8::1  ',
                'domain_names': '  example.com  ,  test.com  ',
            }
        )
        assert form.is_valid()

        ipv4_list = form.cleaned_data['ipv4_addresses']
        assert len(ipv4_list) == 2

        ipv6_list = form.cleaned_data['ipv6_addresses']
        assert len(ipv6_list) == 2

        domain_list = form.cleaned_data['domain_names']
        assert len(domain_list) == 2
        assert 'example.com' in domain_list
        assert 'test.com' in domain_list
