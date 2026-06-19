"""Tests for FreshInstallTlsConfigForm, HsmSetupForm, and BackupRestoreForm."""

from __future__ import annotations

from io import BytesIO

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from setup_wizard.forms import BackupRestoreForm, FreshInstallTlsConfigForm, HsmSetupForm


# ---------------------------------------------------------------------------
# FreshInstallTlsConfigForm — static helpers
# ---------------------------------------------------------------------------


class TestParseCommaSeparatedValues:
    """Tests for FreshInstallTlsConfigForm._parse_comma_separated_values."""

    def test_splits_simple_values(self) -> None:
        """Comma-separated values are split into a trimmed list."""
        result = FreshInstallTlsConfigForm._parse_comma_separated_values('a, b, c')
        assert result == ['a', 'b', 'c']

    def test_ignores_empty_segments(self) -> None:
        """Trailing commas and empty segments are dropped."""
        result = FreshInstallTlsConfigForm._parse_comma_separated_values('a, , b, ')
        assert result == ['a', 'b']

    def test_empty_string_returns_empty_list(self) -> None:
        """Empty input yields an empty list."""
        assert FreshInstallTlsConfigForm._parse_comma_separated_values('') == []

    def test_whitespace_only_is_empty(self) -> None:
        """Whitespace-only segments are dropped."""
        assert FreshInstallTlsConfigForm._parse_comma_separated_values('  ,  ,  ') == []


class TestValidateDnsName:
    """Tests for FreshInstallTlsConfigForm._validate_dns_name."""

    def test_valid_hostname_is_accepted(self) -> None:
        """Simple valid hostnames pass validation."""
        result = FreshInstallTlsConfigForm._validate_dns_name('example.com')
        assert result == 'example.com'

    def test_localhost_is_accepted(self) -> None:
        """'localhost' is a valid DNS name."""
        result = FreshInstallTlsConfigForm._validate_dns_name('localhost')
        assert result == 'localhost'

    def test_valid_subdomain_is_accepted(self) -> None:
        """Subdomains are accepted and lowercased."""
        result = FreshInstallTlsConfigForm._validate_dns_name('Sub.Example.COM')
        assert result == 'sub.example.com'

    def test_trailing_dot_is_stripped(self) -> None:
        """Trailing dot (FQDN notation) is stripped before validation."""
        result = FreshInstallTlsConfigForm._validate_dns_name('example.com.')
        assert result == 'example.com'

    def test_invalid_label_with_leading_hyphen_raises(self) -> None:
        """Labels starting with a hyphen fail validation."""
        from django.forms import ValidationError
        with pytest.raises(ValidationError):
            FreshInstallTlsConfigForm._validate_dns_name('-invalid.com')

    def test_empty_string_raises(self) -> None:
        """Empty string fails validation."""
        from django.forms import ValidationError
        with pytest.raises(ValidationError):
            FreshInstallTlsConfigForm._validate_dns_name('')


class TestCleanIpv4Addresses:
    """Tests for FreshInstallTlsConfigForm.clean_ipv4_addresses."""

    def _make_form(self, ipv4: str) -> FreshInstallTlsConfigForm:
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': ipv4,
            'ipv6_addresses': '::1',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data)
        form.is_valid()
        return form

    def test_valid_single_ipv4(self) -> None:
        """Valid IPv4 address is returned as a string in a list."""
        form = self._make_form('127.0.0.1')
        assert form.cleaned_data['ipv4_addresses'] == ['127.0.0.1']

    def test_valid_multiple_ipv4(self) -> None:
        """Multiple valid IPv4 addresses are returned correctly."""
        form = self._make_form('192.168.1.1, 10.0.0.1')
        assert form.cleaned_data['ipv4_addresses'] == ['192.168.1.1', '10.0.0.1']

    def test_empty_string_returns_empty_list(self) -> None:
        """Empty input returns an empty list."""
        form = self._make_form('')
        assert form.cleaned_data.get('ipv4_addresses') == []

    def test_invalid_ipv4_adds_field_error(self) -> None:
        """Invalid IPv4 address adds a validation error to ipv4_addresses field."""
        form = self._make_form('999.999.999.999')
        assert not form.is_valid()
        assert 'ipv4_addresses' in form.errors


class TestCleanIpv6Addresses:
    """Tests for FreshInstallTlsConfigForm.clean_ipv6_addresses."""

    def _make_form(self, ipv6: str) -> FreshInstallTlsConfigForm:
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': '127.0.0.1',
            'ipv6_addresses': ipv6,
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data)
        form.is_valid()
        return form

    def test_valid_ipv6_loopback(self) -> None:
        """Loopback IPv6 address is accepted."""
        form = self._make_form('::1')
        assert form.cleaned_data['ipv6_addresses'] == ['::1']

    def test_empty_ipv6_returns_empty_list(self) -> None:
        """Empty IPv6 input returns an empty list."""
        form = self._make_form('')
        assert form.cleaned_data.get('ipv6_addresses') == []

    def test_invalid_ipv6_adds_error(self) -> None:
        """Invalid IPv6 address adds a validation error."""
        form = self._make_form('gggg::1')
        # Need isolated form to check error on ipv6 field
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': '',
            'ipv6_addresses': 'gggg::1',
            'domain_names': '',
        }
        f = FreshInstallTlsConfigForm(data=data)
        f.is_valid()
        assert 'ipv6_addresses' in f.errors


class TestCleanDomainNames:
    """Tests for FreshInstallTlsConfigForm.clean_domain_names."""

    def _make_form(self, domain_names: str, extra_san: bool = True) -> FreshInstallTlsConfigForm:
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': '127.0.0.1' if extra_san else '',
            'ipv6_addresses': '',
            'domain_names': domain_names,
        }
        form = FreshInstallTlsConfigForm(data=data)
        form.is_valid()
        return form

    def test_valid_domain_name(self) -> None:
        """Valid domain name is accepted and normalized."""
        form = self._make_form('trustpoint.local')
        assert 'trustpoint.local' in form.cleaned_data.get('domain_names', [])

    def test_empty_domain_names_returns_empty_list(self) -> None:
        """Empty input returns an empty list."""
        form = self._make_form('')
        assert form.cleaned_data.get('domain_names') == []


class TestFreshInstallTlsConfigFormClean:
    """Tests for FreshInstallTlsConfigForm.clean (cross-field mode validation)."""

    def test_generate_mode_requires_at_least_one_san(self) -> None:
        """generate mode with no SANs is invalid."""
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data)
        assert not form.is_valid()
        assert form.non_field_errors()

    def test_generate_mode_with_ipv4_is_valid(self) -> None:
        """generate mode with at least one IPv4 is valid."""
        data = {
            'tls_mode': 'generate',
            'ipv4_addresses': '127.0.0.1',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data)
        assert form.is_valid(), form.errors

    def test_pkcs12_mode_without_file_adds_error(self) -> None:
        """pkcs12 mode without a file adds an error to the pkcs12_file field."""
        data = {
            'tls_mode': 'pkcs12',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data)
        assert not form.is_valid()
        assert 'pkcs12_file' in form.errors

    def test_pkcs12_mode_with_file_is_valid(self) -> None:
        """pkcs12 mode with a file provided passes field-level validation."""
        pkcs12_file = SimpleUploadedFile('cert.p12', b'dummy', content_type='application/x-pkcs12')
        data = {
            'tls_mode': 'pkcs12',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data, files={'pkcs12_file': pkcs12_file})
        # The form is valid at the cross-field level; parsing happens in the view
        assert 'pkcs12_file' not in form.errors

    def test_separate_files_mode_without_cert_adds_error(self) -> None:
        """separate_files mode without TLS cert file adds an error."""
        key_file = SimpleUploadedFile('key.pem', b'key', content_type='application/octet-stream')
        data = {
            'tls_mode': 'separate_files',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data, files={'key_file': key_file})
        assert not form.is_valid()
        assert 'tls_server_certificate' in form.errors

    def test_separate_files_mode_without_key_adds_error(self) -> None:
        """separate_files mode without key file adds an error."""
        cert_file = SimpleUploadedFile('cert.pem', b'cert', content_type='application/octet-stream')
        data = {
            'tls_mode': 'separate_files',
            'ipv4_addresses': '',
            'ipv6_addresses': '',
            'domain_names': '',
        }
        form = FreshInstallTlsConfigForm(data=data, files={'tls_server_certificate': cert_file})
        assert not form.is_valid()
        assert 'key_file' in form.errors


# ---------------------------------------------------------------------------
# HsmSetupForm
# ---------------------------------------------------------------------------


class TestHsmSetupFormInit:
    """Tests for HsmSetupForm.__init__ type-specific defaults."""

    def test_softhsm_defaults(self) -> None:
        """softhsm type pre-fills module_path, slot, and label."""
        form = HsmSetupForm(hsm_type='softhsm')
        assert form.fields['module_path'].initial == '/usr/lib/libpkcs11-proxy.so'
        assert form.fields['slot'].initial == 0
        assert form.fields['label'].initial == 'Trustpoint-SoftHSM'
        assert form.fields['hsm_type'].initial == 'softhsm'

    def test_physical_defaults(self) -> None:
        """physical type leaves module_path blank and sets a label placeholder."""
        form = HsmSetupForm(hsm_type='physical')
        assert form.fields['module_path'].initial == ''
        assert form.fields['label'].initial == 'Trustpoint-Physical-HSM'
        assert form.fields['hsm_type'].initial == 'physical'


class TestHsmSetupFormClean:
    """Tests for HsmSetupForm.clean and field-level clean methods."""

    def _form(self, hsm_type: str, extra: dict | None = None) -> HsmSetupForm:
        data: dict = {
            'hsm_type': hsm_type,
            'module_path': '/usr/lib/libpkcs11-proxy.so',
            'slot': '0',
            'label': 'TestLabel',
        }
        if extra:
            data.update(extra)
        return HsmSetupForm(hsm_type=hsm_type, data=data)

    def test_softhsm_overrides_values(self) -> None:
        """softhsm type forces module_path, slot, and label to fixed values."""
        form = self._form('softhsm')
        assert form.is_valid(), form.errors
        assert form.cleaned_data['module_path'] == '/usr/lib/libpkcs11-proxy.so'
        assert form.cleaned_data['slot'] == 0
        assert form.cleaned_data['label'] == 'Trustpoint-SoftHSM'

    def test_physical_type_raises_validation_error(self) -> None:
        """physical HSM type raises a form-level ValidationError."""
        form = self._form('physical')
        assert not form.is_valid()
        assert any('not yet supported' in str(e) for e in form.non_field_errors())

    def test_unknown_type_adds_field_error(self) -> None:
        """Unknown HSM type adds an error to the hsm_type field."""
        form = self._form('unknown_hsm')
        assert not form.is_valid()
        assert 'hsm_type' in form.errors or form.non_field_errors()


# ---------------------------------------------------------------------------
# BackupRestoreForm
# ---------------------------------------------------------------------------


class TestBackupRestoreFormCleanBackupFile:
    """Tests for BackupRestoreForm.clean_backup_file."""

    def _make_form(self, filename: str, content: bytes = b'data', size: int | None = None) -> BackupRestoreForm:
        file_obj = SimpleUploadedFile(filename, content, content_type='application/octet-stream')
        if size is not None:
            file_obj.size = size
        return BackupRestoreForm(data={}, files={'backup_file': file_obj})

    def test_valid_dump_extension(self) -> None:
        """Files with .dump extension pass validation."""
        form = self._make_form('backup.dump')
        assert 'backup_file' not in form.errors

    def test_valid_gz_extension(self) -> None:
        """Files with .gz extension pass validation."""
        form = self._make_form('backup.gz')
        assert 'backup_file' not in form.errors

    def test_valid_sql_extension(self) -> None:
        """Files with .sql extension pass validation."""
        form = self._make_form('backup.sql')
        assert 'backup_file' not in form.errors

    def test_valid_zip_extension(self) -> None:
        """Files with .zip extension pass validation."""
        form = self._make_form('backup.zip')
        assert 'backup_file' not in form.errors

    def test_invalid_extension_fails(self) -> None:
        """Files with disallowed extensions fail validation."""
        form = self._make_form('backup.txt')
        form.is_valid()
        assert 'backup_file' in form.errors

    def test_file_too_large_fails(self) -> None:
        """Files exceeding 100 MB fail validation."""
        form = self._make_form('backup.dump', size=101 * 1024 * 1024)
        form.is_valid()
        assert 'backup_file' in form.errors

    def test_missing_file_fails(self) -> None:
        """Submitting without a file fails validation."""
        form = BackupRestoreForm(data={}, files={})
        form.is_valid()
        assert 'backup_file' in form.errors


class TestBackupRestoreFormCleanBackupPassword:
    """Tests for BackupRestoreForm.clean_backup_password."""

    def _make_form(self, password: str) -> BackupRestoreForm:
        file_obj = SimpleUploadedFile('backup.dump', b'data')
        return BackupRestoreForm(data={'backup_password': password}, files={'backup_file': file_obj})

    def test_empty_password_is_allowed(self) -> None:
        """An empty backup password is allowed (not required)."""
        form = self._make_form('')
        assert form.is_valid(), form.errors
        assert form.cleaned_data['backup_password'] == ''

    def test_valid_password_is_accepted(self) -> None:
        """A valid password within length limit is accepted."""
        form = self._make_form('valid-password')
        assert form.is_valid(), form.errors
        assert form.cleaned_data['backup_password'] == 'valid-password'

    def test_password_exceeding_max_length_fails(self) -> None:
        """Password longer than MAX_PASSWORD_LENGTH raises a validation error."""
        long_password = 'x' * (BackupRestoreForm.MAX_PASSWORD_LENGTH + 1)
        form = self._make_form(long_password)
        form.is_valid()
        assert 'backup_password' in form.errors
