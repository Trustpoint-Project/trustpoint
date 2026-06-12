"""Tests for fresh-install setup-wizard forms."""

from __future__ import annotations

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from setup_wizard.forms import (
    DEFAULT_PKCS11_CONFIG_ENV_VAR,
    FreshInstallBackendConfigModelForm,
    FreshInstallTlsConfigForm,
    RestoreBackupImportForm,
)
from setup_wizard.models import SetupWizardConfigModel

SLOT_ID = 3


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
# FreshInstallBackendConfigModelForm
# ---------------------------------------------------------------------------


class TestFreshInstallBackendConfigModelForm:
    """Tests for PKCS#11 backend configuration validation."""

    @staticmethod
    def _instance(
        crypto_storage: SetupWizardConfigModel.CryptoStorageType = SetupWizardConfigModel.CryptoStorageType.HsmStorage,
    ) -> SetupWizardConfigModel:
        instance = SetupWizardConfigModel(crypto_storage=crypto_storage)
        instance.fresh_install_pkcs11_token_label = ''
        instance.fresh_install_pkcs11_module_path = ''
        instance.fresh_install_pkcs11_auth_source_ref = ''
        instance.fresh_install_pkcs11_config_path = ''
        return instance

    def _form(
        self,
        extra: dict[str, object] | None = None,
        files: dict[str, SimpleUploadedFile] | None = None,
        *,
        instance: SetupWizardConfigModel | None = None,
    ) -> FreshInstallBackendConfigModelForm:
        data: dict = {
            'fresh_install_pkcs11_token_label': 'Trustpoint-SoftHSM',  # noqa: S105 - token label, not a password.
            'fresh_install_pkcs11_slot_id': '',
            'pkcs11_user_pin': '1234',
            'pkcs11_config_env_var': '',
        }
        if extra:
            data.update(extra)
        return FreshInstallBackendConfigModelForm(data=data, files=files or {}, instance=instance or self._instance())

    def test_software_backend_hides_pkcs11_fields(self) -> None:
        """Software backend mode keeps PKCS#11 fields hidden and optional."""
        form = self._form(instance=self._instance(SetupWizardConfigModel.CryptoStorageType.SoftwareStorage))
        assert form.is_valid(), form.errors
        assert form.cleaned_data['fresh_install_pkcs11_token_label'] == ''
        assert form.cleaned_data['fresh_install_pkcs11_slot_id'] is None

    def test_hsm_backend_requires_module_pin_and_selector(self) -> None:
        """PKCS#11 mode requires a module, PIN, and at least one token selector."""
        form = self._form(
            {
                'fresh_install_pkcs11_token_label': '',
                'fresh_install_pkcs11_slot_id': '',
                'pkcs11_user_pin': '',
            }
        )
        assert not form.is_valid()
        assert 'pkcs11_module_upload' in form.errors
        assert 'pkcs11_user_pin' in form.errors
        assert 'fresh_install_pkcs11_token_label' in form.errors

    def test_hsm_backend_accepts_valid_elf_module_and_label(self) -> None:
        """PKCS#11 mode accepts a valid ELF shared library upload and token label."""
        module_file = SimpleUploadedFile(
            'libpkcs11.so',
            b'\x7fELFdummy',
            content_type='application/octet-stream',
        )
        form = self._form(files={'pkcs11_module_upload': module_file})
        assert form.is_valid(), form.errors
        assert form.cleaned_data['fresh_install_pkcs11_token_label'] == 'Trustpoint-SoftHSM'  # noqa: S105

    def test_hsm_backend_accepts_slot_only_selector(self) -> None:
        """PKCS#11 mode can select a token by slot ID without a label."""
        module_file = SimpleUploadedFile(
            'libpkcs11.so',
            b'\x7fELFdummy',
            content_type='application/octet-stream',
        )
        form = self._form(
            {
                'fresh_install_pkcs11_token_label': '',
                'fresh_install_pkcs11_slot_id': str(SLOT_ID),
            },
            files={'pkcs11_module_upload': module_file},
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['fresh_install_pkcs11_slot_id'] == SLOT_ID

    def test_vendor_config_upload_defaults_env_var(self) -> None:
        """Uploading a vendor config without an env var uses the Utimaco default."""
        module_file = SimpleUploadedFile(
            'libpkcs11.so',
            b'\x7fELFdummy',
            content_type='application/octet-stream',
        )
        config_file = SimpleUploadedFile('cs_pkcs11_R3.cfg', b'[Global]\n')
        form = self._form(
            files={
                'pkcs11_module_upload': module_file,
                'pkcs11_config_upload': config_file,
            }
        )
        assert form.is_valid(), form.errors
        assert form.cleaned_data['pkcs11_config_env_var'] == DEFAULT_PKCS11_CONFIG_ENV_VAR


# ---------------------------------------------------------------------------
# RestoreBackupImportForm
# ---------------------------------------------------------------------------


class TestRestoreBackupImportFormCleanBackupArchive:
    """Tests for RestoreBackupImportForm.clean_backup_archive."""

    def _make_form(self, filename: str, content: bytes = b'data') -> RestoreBackupImportForm:
        file_obj = SimpleUploadedFile(filename, content, content_type='application/octet-stream')
        return RestoreBackupImportForm(data={}, files={'backup_archive': file_obj})

    def test_valid_dump_extension(self) -> None:
        """Files with .dump extension pass validation."""
        form = self._make_form('backup.dump')
        assert form.is_valid(), form.errors

    def test_valid_dump_gz_extension(self) -> None:
        """Files with .dump.gz extension pass validation."""
        form = self._make_form('backup.dump.gz')
        assert form.is_valid(), form.errors

    def test_valid_gpg_extension(self) -> None:
        """Encrypted dump variants pass validation."""
        form = self._make_form('backup.dump.gz.gpg')
        assert form.is_valid(), form.errors

    def test_invalid_extension_fails(self) -> None:
        """Files with disallowed extensions fail validation."""
        form = self._make_form('backup.txt')
        form.is_valid()
        assert 'backup_archive' in form.errors

    def test_missing_file_fails(self) -> None:
        """Submitting without a file fails validation."""
        form = RestoreBackupImportForm(data={}, files={})
        form.is_valid()
        assert 'backup_archive' in form.errors

    def test_missing_file_is_allowed_when_archive_already_staged(self) -> None:
        """A previously staged archive allows continuing without uploading again."""
        config_model = SetupWizardConfigModel(restore_backup_archive_original_name='backup.dump')
        form = RestoreBackupImportForm(data={}, files={}, config_model=config_model)
        assert form.is_valid(), form.errors


class TestRestoreBackupImportFormPassword:
    """Tests for RestoreBackupImportForm backup password handling."""

    def _make_form(self, password: str) -> RestoreBackupImportForm:
        file_obj = SimpleUploadedFile('backup.dump', b'data')
        return RestoreBackupImportForm(
            data={'backup_archive_password': password},
            files={'backup_archive': file_obj},
        )

    def test_empty_password_is_allowed(self) -> None:
        """An empty backup password is allowed (not required)."""
        form = self._make_form('')
        assert form.is_valid(), form.errors
        assert form.cleaned_data['backup_archive_password'] == ''

    def test_valid_password_is_accepted(self) -> None:
        """A backup password is accepted when provided."""
        form = self._make_form('valid-password')
        assert form.is_valid(), form.errors
        assert form.cleaned_data['backup_archive_password'] == 'valid-password'  # noqa: S105 - test password value.
