"""Forms definition."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, cast
from zoneinfo import available_timezones

from crispy_bootstrap5.bootstrap5 import Field
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Fieldset, Layout
from cryptography.x509 import Certificate
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from management.models import (
    BackupOptions,
    InternationalizationConfig,
    KeyStorageConfig,
    LoggingConfig,
    NotificationConfig,
    PKCS11Token,
    SecurityConfig,
)
from management.security import manager
from management.security.features import AutoGenPkiFeature, SecurityFeature
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from pki.models import CredentialModel
from pki.util.keys import AutoGenPkiKeyAlgorithm
from pki.util.x509 import CertificateVerifier
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from typing import ClassVar


class SecurityConfigForm(forms.ModelForm[SecurityConfig]):
    """Security configuration model form."""

    FEATURE_TO_FIELDS: ClassVar[dict[type[SecurityFeature], list[str]]] = {
        AutoGenPkiFeature: ['auto_gen_pki', 'auto_gen_pki_key_algorithm'],
    }

    def __init__(self, *args: Any, **kwargs: Any)-> None:
        """Initialize the SecurityConfigForm."""
        super().__init__(*args, **kwargs)

        # Determine the 'current_mode' from form data or instance
        if 'security_mode' in self.data:
            current_mode = self.data['security_mode']
        else:
            current_mode = (
                self.instance.security_mode if self.instance else SecurityConfig.SecurityModeChoices.BROWNFIELD
            )

        sec_manager = manager.SecurityManager()
        features_not_allowed = sec_manager.get_features_to_disable(current_mode)

        # Disable form fields that correspond to features not allowed
        for feature_cls in features_not_allowed:
            field_names = self.FEATURE_TO_FIELDS.get(type(feature_cls), [])
            for field_name in field_names:
                if field_name in self.fields:
                    self.fields[field_name].widget.attrs['disabled'] = 'disabled'

        # Disable option to change algorithm if AutoGenPKI is already enabled
        if self.instance and self.instance.auto_gen_pki:
            self.fields['auto_gen_pki_key_algorithm'].widget.attrs['disabled'] = 'disabled'

        self.helper = FormHelper()
        self.helper.layout = Layout(
            Fieldset(
                _('Security level presets'),
                'security_mode',
            ),
            Fieldset(
                _('Advanced security settings'),
                Field('auto_gen_pki', wrapper_class='form-check form-switch'),
                'auto_gen_pki_key_algorithm',
                # Add all the new fields below so they render in the UI
                'rsa_minimum_key_size',
                'max_cert_validity_days',
                'max_crl_validity_days',
                Field('allow_ca_issuance', wrapper_class='form-check form-switch'),
                Field('allow_auto_gen_pki', wrapper_class='form-check form-switch'),
                Field('allow_self_signed_ca', wrapper_class='form-check form-switch'),
                Field('require_physical_hsm', wrapper_class='form-check form-switch'),
                'permitted_no_onboarding_pki_protocols',
                'permitted_onboarding_protocols'
            ),
        )

    security_mode = forms.ChoiceField(
        choices=SecurityConfig.SecurityModeChoices, widget=forms.RadioSelect(), label=''
    )

    auto_gen_pki = forms.BooleanField(
        required=False,
        label=_('Enable local auto-generated PKI'),
        widget=forms.CheckboxInput(
            attrs={
                'class': 'form-check-input',
                'role': 'switch',
                'data-sl-defaults': '[true, true, false, false, false]',
                'data-hide-at-sl': '[false, false, true, true, true]',
                'data-more-secure': 'false',
            }
        ),
    )

    auto_gen_pki_key_algorithm = forms.ChoiceField(
        choices=AutoGenPkiKeyAlgorithm,
        label=_('Key Algorithm for auto-generated PKI'),
        required=False,
        widget=forms.Select(attrs={'data-hide-at-sl': '[false, false, true, true, true]'}),
    )

    RSA_KEY_CHOICES : ClassVar[list[tuple[object, str]]] = [
        ('', _('None / Not Permitted')),
        (1024, '1024'), (2048, '2048'), (3072, '3072'), (4096, '4096'), (8192, '8192')
    ]
    rsa_minimum_key_size = forms.ChoiceField(
        choices=RSA_KEY_CHOICES, required=False, widget=forms.Select()
    )

    permitted_no_onboarding_pki_protocols = forms.MultipleChoiceField(
        choices=[(c.value, c.label) for c in NoOnboardingPkiProtocol],
        widget=forms.CheckboxSelectMultiple, required=False
    )
    permitted_onboarding_protocols = forms.MultipleChoiceField(
        choices=[(c.value, c.label) for c in OnboardingProtocol],
        widget=forms.CheckboxSelectMultiple, required=False
    )

    class Meta:
        """Meta configuration for SecurityConfigForm."""
        model = SecurityConfig
        fields: ClassVar[list[str]] = [
            'security_mode', 'auto_gen_pki', 'auto_gen_pki_key_algorithm',
            'rsa_minimum_key_size', 'max_cert_validity_days', 'max_crl_validity_days',
            'allow_ca_issuance', 'allow_auto_gen_pki', 'allow_self_signed_ca',
            'require_physical_hsm', 'permitted_no_onboarding_pki_protocols',
            'permitted_onboarding_protocols'
        ]

    def clean_rsa_minimum_key_size(self) -> int | None:
        """Normalize RSA minimum key size.

        - '' -> None
        - for CRITICAL: always None (RSA banned)
        - otherwise: convert to int
        """
        raw = self.cleaned_data.get('rsa_minimum_key_size')
        mode = self.cleaned_data.get('security_mode')


        if mode == SecurityConfig.SecurityModeChoices.CRITICAL:
            return None


        if raw in (None, ''):
            return None

        try:
            return int(raw)
        except (TypeError, ValueError) as err:
            raise ValidationError(_('Invalid RSA key size.')) from err
    def clean_auto_gen_pki_key_algorithm(self) -> AutoGenPkiKeyAlgorithm:
        """Keep the current value of `auto_gen_pki_key_algorithm` from the instance if the field was disabled."""
        form_value = self.cleaned_data.get('auto_gen_pki_key_algorithm')
        if form_value is None or form_value == '':
            if self.instance:
                return AutoGenPkiKeyAlgorithm(self.instance.auto_gen_pki_key_algorithm)
            return AutoGenPkiKeyAlgorithm.RSA2048
        return AutoGenPkiKeyAlgorithm(form_value)

    def clean(self) -> dict[str, Any]:
        """Apply per-mode constraints on security settings."""
        cleaned_data = super().clean()
        mode = cleaned_data.get('security_mode')

        # Enforce limits if not in Lab / Custom mode
        if mode != SecurityConfig.SecurityModeChoices.LAB:
            defaults = SecurityConfig._MODE_DEFAULTS[mode]  # noqa: SLF001

            # Numeric: Custom must be <= Default (max valid days)
            for field in ['max_cert_validity_days', 'max_crl_validity_days']:
                val = cleaned_data.get(field)
                default_val = defaults.get(field)
                if default_val is not None and (val is None or val > default_val):
                    self.add_error(field, f'Maximum allowed for this level is {default_val}.')

            # Minimums: Custom must be >= Default (RSA size)
            rsa_val = int(cleaned_data.get('rsa_minimum_key_size') or 0)
            default_rsa = defaults.get('rsa_minimum_key_size')
            if default_rsa is not None and rsa_val < default_rsa:
                self.add_error('rsa_minimum_key_size', f'Minimum key size for this level is {default_rsa}.')

            # Booleans: Cannot enable if default is False
            for field in ['allow_ca_issuance', 'allow_auto_gen_pki', 'allow_self_signed_ca']:
                if not defaults.get(field) and cleaned_data.get(field):
                    self.add_error(field, 'This feature cannot be enabled at this security level.')

        return cleaned_data


class NotificationConfigForm(forms.ModelForm[NotificationConfig]):
    """Form for managing global notification configuration settings."""

    MAX_EXPIRY_WARNING_DAYS = 365
    MIN_EXPIRY_WARNING_DAYS = 1

    class Meta:
        """Meta configuration for NotificationConfigForm."""
        model = NotificationConfig
        fields: ClassVar[list[str]] = [
            'enabled',
            'cert_expiry_warning_days',
            'issuing_ca_expiry_warning_days',
        ]
        widgets: ClassVar[dict[str, Any]] = {
            'enabled': forms.CheckboxInput(
                attrs={'class': 'form-check-input'}
            ),
            'cert_expiry_warning_days': forms.NumberInput(
                attrs={'class': 'form-control', 'min': '1', 'max': '365'}
            ),
            'issuing_ca_expiry_warning_days': forms.NumberInput(
                attrs={'class': 'form-control', 'min': '1', 'max': '365'}
            ),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the NotificationConfigForm."""
        super().__init__(*args, **kwargs)

        self.helper = FormHelper()
        self.helper.form_tag = False
        self.helper.layout = Layout(
            Fieldset(
                _('Notification Settings'),
                'enabled',
            ),
            Fieldset(
                _('Expiry Warning Thresholds'),
                'cert_expiry_warning_days',
                'issuing_ca_expiry_warning_days',
            ),
        )

    def clean_cert_expiry_warning_days(self) -> int | None:
        """Validate cert_expiry_warning_days field."""
        cert_expiry = self.cleaned_data.get('cert_expiry_warning_days')
        if cert_expiry is not None and (
            cert_expiry < self.MIN_EXPIRY_WARNING_DAYS or
            cert_expiry > self.MAX_EXPIRY_WARNING_DAYS
        ):
            raise ValidationError(
                _('Value must be between %(min)d and %(max)d days.') % {
                    'min': self.MIN_EXPIRY_WARNING_DAYS,
                    'max': self.MAX_EXPIRY_WARNING_DAYS,
                }
            )
        return cert_expiry

    def clean_issuing_ca_expiry_warning_days(self) -> int | None:
        """Validate issuing_ca_expiry_warning_days field."""
        ca_expiry = self.cleaned_data.get('issuing_ca_expiry_warning_days')
        if ca_expiry is not None and (
            ca_expiry < self.MIN_EXPIRY_WARNING_DAYS or
            ca_expiry > self.MAX_EXPIRY_WARNING_DAYS
        ):
            raise ValidationError(
                _('Value must be between %(min)d and %(max)d days.') % {
                    'min': self.MIN_EXPIRY_WARNING_DAYS,
                    'max': self.MAX_EXPIRY_WARNING_DAYS,
                }
            )
        return ca_expiry

class BackupOptionsForm(forms.ModelForm[BackupOptions]):
    """Form for editing BackupOptions settings."""

    class Meta:
        """ModelForm Meta configuration for BackupOptions."""
        model = BackupOptions
        fields: ClassVar[list[str]] = [
            'enable_sftp_storage',
            'host',
            'port',
            'user',
            'auth_method',
            'password',
            'private_key',
            'key_passphrase',
            'remote_directory',
        ]
        widgets: ClassVar[dict[str, Any]] = {
            'enable_sftp_storage': forms.CheckboxInput(attrs={'class': 'form-check-input', 'role': 'switch'}),
            'host': forms.TextInput(attrs={'class': 'form-control'}),
            'port': forms.NumberInput(attrs={'class': 'form-control'}),
            'user': forms.TextInput(attrs={'class': 'form-control'}),
            'auth_method': forms.Select(attrs={'class': 'form-select'}),
            'password': forms.PasswordInput(
                attrs={'class': 'form-control'}, render_value=True
            ),
            'private_key': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
            'key_passphrase': forms.PasswordInput(
                attrs={'class': 'form-control'}, render_value=True
            ),
            'remote_directory': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def clean(self) -> dict[str, Any]:
        """Validate required fields based on selected authentication method."""
        cleaned: dict[str, Any] = super().clean() or {}
        auth = cleaned.get('auth_method')
        enable_sftp = cleaned.get('enable_sftp_storage')

        if enable_sftp:
            self._validate_sftp_fields(cleaned)
            self._validate_authentication_fields(cleaned, auth)

        return cleaned

    def _validate_sftp_fields(self, cleaned: dict[str, Any]) -> None:
        """Validate required fields for SFTP storage."""
        missing_fields = []
        host = cleaned.get('host', '').strip()
        user = cleaned.get('user', '').strip()
        remote_directory = cleaned.get('remote_directory', '').strip()

        if not host:
            missing_fields.append('Host')
        if not user:
            missing_fields.append('Username')
        if not remote_directory:
            missing_fields.append('Remote Directory')

        if missing_fields:
            self.add_error(
                None,
                f"The following fields are required when SFTP storage is enabled: {', '.join(missing_fields)}."
            )

    def _validate_authentication_fields(self, cleaned: dict[str, Any], auth: Any) -> None:
        """Validate fields based on the selected authentication method."""
        pwd = cleaned.get('password', '').strip()
        key = cleaned.get('private_key', '').strip()

        if auth == BackupOptions.AuthMethod.PASSWORD:
            self._validate_password_authentication(pwd, key, cleaned)
        elif auth == BackupOptions.AuthMethod.SSH_KEY:
            self._validate_ssh_key_authentication(pwd, key)

    def _validate_password_authentication(self, pwd: str, key: str, cleaned: dict[str, Any]) -> None:
        """Validate fields for password authentication."""
        if not pwd:
            self.add_error('password', 'Password is required when using password authentication.')
        if key or cleaned.get('key_passphrase', '').strip():
            self.add_error('private_key',
                           'Private key and passphrase must be empty when using password authentication.')
            self.add_error('key_passphrase',
                           'Private key and passphrase must be empty when using password authentication.')

    def _validate_ssh_key_authentication(self, pwd: str, key: str) -> None:
        """Validate fields for SSH key authentication."""
        if not key:
            self.add_error('private_key', 'Private key is required when using SSH Key authentication.')
        if pwd:
            self.add_error('password', 'Password must be empty when using SSH key authentication.')

class IPv4AddressForm(forms.Form):
    """A form for selecting and updating an IPv4 address.

    This form provides an interface for selecting an IPv4 address from
    a list of Subject Alternative Names (SANs).

    Attributes:
        ipv4_address: A choice field for selecting the IPv4 address.
    """

    ipv4_address = forms.ChoiceField(
        label='Update IPv4 Address'
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the IPv4AddressForm."""
        san_ips = kwargs.pop('san_ips', [])
        saved_ipv4_address = kwargs.get('initial', {}).get('ipv4_address')

        if saved_ipv4_address and saved_ipv4_address not in san_ips:
            san_ips.insert(0, saved_ipv4_address)

        super().__init__(*args, **kwargs)

        ipv4_field = cast('forms.ChoiceField', self.fields['ipv4_address'])
        ipv4_field.choices = [(ip, ip) for ip in san_ips]

class TlsAddFileImportPkcs12Form(LoggerMixin, forms.Form):
    """Form for importing an TLS-Server Credential using a PKCS#12 file.

    This form allows the user to upload a PKCS#12 file containing the private key
    and certificate chain, along with an optional password. It validates the
    uploaded file and its contents.

    Attributes:
        pkcs12_file (FileField): The PKCS#12 file containing the private key and certificates.
        pkcs12_password (CharField): An optional password for the PKCS#12 file.
    """

    pkcs12_file = forms.FileField(label=_('PKCS#12 File (.p12, .pfx)'), required=True)
    pkcs12_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code  # noqa: FIX004
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] PKCS#12 password'),
        required=False,
    )
    domain_name = forms.CharField(
        label=_('Domain-Name'), initial='localhost', required=False,
            validators=[
              RegexValidator(
                  regex=r'^localhost$|^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$',
                  message='Enter a valid domain name (e.g. example.com).'
              )
        ]
    )

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Raises a validation error with the given message."""
        raise ValidationError(message)

    def _read_pkcs12_file(self, cleaned_data: dict[str, Any]) -> tuple[bytes, Any, Any]:
        """Read and extract data from PKCS#12 file.

        Returns:
            Tuple of (pkcs12_raw, pkcs12_password, domain_name)
        """
        pkcs12_file = cleaned_data.get('pkcs12_file')
        if pkcs12_file is None:
            self._raise_validation_error('No PKCS#12 file was uploaded.')

        try:
            pkcs12_raw = pkcs12_file.read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
            domain_name = cleaned_data.get('domain_name')
        except (OSError, AttributeError) as original_exception:
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.'
            )
            raise ValidationError(error_message, code='unexpected-error') from original_exception
        else:
            return pkcs12_raw, pkcs12_password, domain_name

    def _encode_password(self, pkcs12_password: Any) -> bytes | None:
        """Encode PKCS#12 password if provided.

        Returns:
            Encoded password bytes or None if no password provided
        """
        if pkcs12_password:
            try:
                encoded: bytes = pkcs12_password.encode()
            except Exception as original_exception:
                error_message = _('The PKCS#12 password contains invalid data, that cannot be encoded in UTF-8.')
                raise ValidationError(error_message) from original_exception
            else:
                return encoded
        return None

    def _parse_and_save_credential(
        self, pkcs12_raw: bytes, pkcs12_password: bytes | None, domain_name: Any
    ) -> None:
        """Parse PKCS#12 data and save credential."""
        try:
            tls_credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, pkcs12_password)
        except Exception as exception:
            err_msg = _('Failed to parse and load the uploaded file. Either wrong password or corrupted file.')
            raise ValidationError(err_msg) from exception

        try:
            certificate = tls_credential_serializer.certificate
            if certificate is None:
                self._raise_validation_error('The provided PKCS#12 file does not contain a valid certificate.')
            if not isinstance(certificate, Certificate):
                self._raise_validation_error('Invalid credential: certificate is not a valid x509.Certificate.')

            # At this point, both isinstance and None checks guarantee certificate is Certificate
            # For self-signed certificates, treat the certificate itself as a trusted root
            trusted_roots = [certificate] if certificate.issuer == certificate.subject else []
            untrusted_intermediates = tls_credential_serializer.additional_certificates or []

            CertificateVerifier.verify_server_cert(
                certificate,
                domain_name,
                trusted_roots=trusted_roots,
                untrusted_intermediates=untrusted_intermediates
            )
            self.saved_credential = CredentialModel.save_credential_serializer(
                credential_serializer=tls_credential_serializer,
                credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
            )
        except ValidationError:
            raise
        except Exception as exception:
            error_msg = str(exception)
            raise ValidationError(error_msg) from exception

    def clean(self) -> None:
        """Cleans and validates the entire form.

        This method performs additional validation on the cleaned data to ensure
        all required fields are valid and consistent. It checks the uploaded PKCS#12
        file and its password (if provided). Any issues during validation
        raise appropriate errors.

        Raises:
            ValidationError: If the data is invalid, such as when the unique name
            is already taken or the PKCS#12 file cannot be read or parsed.
        """
        cleaned_data = super().clean()
        if not cleaned_data:
            exc_msg = 'No data was provided.'
            raise ValidationError(exc_msg)

        pkcs12_raw, pkcs12_password, domain_name = self._read_pkcs12_file(cleaned_data)
        pkcs12_password_bytes = self._encode_password(pkcs12_password)
        self._parse_and_save_credential(pkcs12_raw, pkcs12_password_bytes, domain_name)

    def get_saved_credential(self) -> CredentialModel:
        """Return the saved credential."""
        return self.saved_credential

class TlsAddFileImportSeparateFilesForm(LoggerMixin, forms.Form):
    """Form for importing a TLS-Server Credential using separate files.

    This form allows the user to upload a private key file, its password (optional),
    an TLS certificate file, and an optional certificate chain. The form
    validates the uploaded files, ensuring they are correctly formatted, within
    size limits, and not already associated with an existing Issuing CA.

    Attributes:
        private_key_file (FileField): The private key file (.key, .pem).
        private_key_file_password (CharField): An optional password for the private key.
        tls_certificate (FileField): The Issuing CA certificate file (.cer, .der, .pem, .p7b, .p7c).
        tls_certificate_chain (FileField): An optional certificate chain file.
    """

    tls_certificate = forms.FileField(label=_('TLS Certificate (.cer, .der, .pem, .p7b, .p7c)'), required=True)
    tls_certificate_chain = forms.FileField(label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c).'), required=False)
    private_key_file = forms.FileField(label=_('Private Key File (.key, .pem)'), required=True)
    private_key_file_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code  # noqa: FIX004
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password'),
        required=False,
    )
    domain_name = forms.CharField(
        label=_('Domain-Name'), initial='localhost', required=False,
            validators=[
              RegexValidator(
                  regex=r'^localhost$|^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$',
                  message='Enter a valid domain name (e.g. example.com).'
              )
        ]
    )

    def clean_private_key_file(self) -> bytes:
        """Validates the uploaded private key file.

        This method checks if the private key file is provided and ensures it meets
        size constraints. The actual parsing happens in clean() where the password is available.

        Returns:
            bytes: The raw bytes of the private key file.

        Raises:
            ValidationError: If the private key file is missing or too large.
        """
        private_key_file = self.cleaned_data.get('private_key_file')

        if not private_key_file:
            err_msg = 'No private key file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if private_key_file.size > max_size:
            err_msg = 'Private key file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        return bytes(private_key_file.read())

    def clean_tls_certificate(self) -> CertificateSerializer:
        """Validates and parses the uploaded TLS certificate file.

        This method ensures the provided TLS certificate file is valid and
        not already associated with an existing TLS in the database. If the
        file is too large, corrupted, or already in use, a validation error is raised.

        Returns:
            CertificateSerializer: A serializer containing the parsed certificate.

        Raises:
            ValidationError: If the file is missing, too large, corrupted, or already
            associated with an existing TLS.
        """
        tls_certificate = self.cleaned_data['tls_certificate']

        if not tls_certificate:
            err_msg = 'No TLS certificate file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if tls_certificate.size > max_size:
            err_msg = 'TLS certificate file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        try:
            certificate_serializer = CertificateSerializer.from_bytes(tls_certificate.read())
        except Exception as exception:
            err_msg = 'Failed to parse the TLS certificate. Seems to be corrupted.'
            raise ValidationError(err_msg) from exception

        return certificate_serializer

    def clean_tls_certificate_chain(self) -> None | CertificateCollectionSerializer:
        """Validates and parses the uploaded TLS certificate chain file."""
        tls_certificate_chain = self.cleaned_data['tls_certificate_chain']

        if tls_certificate_chain:
            try:
                return CertificateCollectionSerializer.from_bytes(tls_certificate_chain.read())
            except Exception as exception:
                err_msg = _('Failed to parse the TLS certificate chain. Seems to be corrupted.')
                raise ValidationError(err_msg) from exception

        return None

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Raises a validation error with the given message."""
        raise forms.ValidationError(message)

    def _encode_private_key_password(self, private_key_password: Any) -> bytes | None:
        """Encode private key password if provided."""
        if private_key_password:
            try:
                encoded: bytes = private_key_password.encode()
            except Exception as original_exception:
                error_message = 'The private key password contains invalid data that cannot be encoded in UTF-8.'
                raise ValidationError(error_message) from original_exception
            else:
                return encoded
        return None

    def _parse_private_key(self, private_key_bytes: bytes, private_key_password_bytes: bytes | None) -> Any:
        """Parse private key with optional password."""
        try:
            return PrivateKeySerializer.from_bytes(private_key_bytes, private_key_password_bytes)
        except Exception as exception:
            err_msg = _('Failed to parse the private key file. Either wrong password or file corrupted.')
            raise ValidationError(err_msg) from exception

    def _create_and_save_credential(
        self,
        private_key_serializer: Any,
        tls_certificate_serializer: Any,
        tls_certificate_chain_serializer: Any,
        domain_name: str
    ) -> None:
        """Create credential from serializers, verify, and save."""
        credential_serializer = CredentialSerializer.from_serializers(
            private_key_serializer=private_key_serializer,
            certificate_serializer=tls_certificate_serializer,
            certificate_collection_serializer=tls_certificate_chain_serializer
        )

        certificate = credential_serializer.certificate
        if certificate is None:
            self._raise_validation_error('Invalid credential: certificate is not a valid x509.Certificate.')
        if not isinstance(certificate, Certificate):
            self._raise_validation_error('Invalid credential: certificate is not a valid x509.Certificate.')

        # At this point, both isinstance and None checks guarantee certificate is Certificate
        # For self-signed certificates, treat the certificate itself as a trusted root
        trusted_roots = [certificate] if certificate.issuer == certificate.subject else []
        untrusted_intermediates = credential_serializer.additional_certificates or []

        CertificateVerifier.verify_server_cert(
            certificate,
            domain_name,
            trusted_roots=trusted_roots,
            untrusted_intermediates=untrusted_intermediates
        )

        self.saved_credential = CredentialModel.save_credential_serializer(
            credential_serializer=credential_serializer,
            credential_type=CredentialModel.CredentialTypeChoice.TRUSTPOINT_TLS_SERVER,
        )

    def clean(self) -> dict[str, Any] | None:
        """Cleans and validates the form data.

        This method performs additional validation on the provided data,
        such as ensuring the private key file, and certificates
        are valid. It also activates and saves the TLS certificate
        if all checks pass.

        Raises:
            ValidationError: If the form data is invalid or there is an error during processing.
        """
        try:
            cleaned_data = super().clean()
            if not cleaned_data:
                return cleaned_data

            private_key_bytes = cleaned_data.get('private_key_file')
            private_key_password = cleaned_data.get('private_key_file_password')
            tls_certificate_serializer = cleaned_data.get('tls_certificate')
            tls_certificate_chain_serializer = (
                cleaned_data.get('tls_certificate_chain') if cleaned_data.get('tls_certificate_chain') else None
            )
            domain_name = cleaned_data.get('domain_name')

            try:
                domain_name = str(domain_name)
            except Exception as original_exception:
                err_msg = _('The provided domain name is invalid.')
                raise ValidationError(err_msg) from original_exception

            if not private_key_bytes or not tls_certificate_serializer:
                return cleaned_data

            private_key_password_bytes = self._encode_private_key_password(private_key_password)
            private_key_serializer = self._parse_private_key(private_key_bytes, private_key_password_bytes)
            self._create_and_save_credential(
                private_key_serializer,
                tls_certificate_serializer,
                tls_certificate_chain_serializer,
                domain_name
            )
        except ValidationError:
            raise
        except Exception as exception:
            error_msg = str(exception)
            raise ValidationError(error_msg) from exception
        else:
            return None

    def get_saved_credential(self) -> CredentialModel:
        """Return the saved credential."""
        return self.saved_credential

class KeyStorageConfigForm(forms.ModelForm[KeyStorageConfig]):
    """Form for configuring cryptographic material storage options."""

    storage_type = forms.ChoiceField(
        widget=forms.RadioSelect,
        label=_('Storage Type'),
        help_text=_('Select how cryptographic material should be stored'),
        choices=[
            ('software', _('Software Storage')),
            ('softhsm', _('SoftHSM Container')),
            ('physical_hsm', _('Physical HSM')),
        ]
    )

    class Meta:
        """ModelForm Meta configuration for KeyStorageConfig."""
        model = KeyStorageConfig
        fields: ClassVar[list[str]] = ['storage_type']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data: dict[str, Any] = super().clean() or {}
        return cleaned_data

    def save_with_commit(self) -> KeyStorageConfig:
        """Save the form with commit, ensuring singleton behavior."""
        instance = KeyStorageConfig.get_or_create_default()
        instance.storage_type = self.cleaned_data['storage_type']
        instance.save(update_fields=['storage_type', 'last_updated'])
        return instance

    def save_without_commit(self) -> KeyStorageConfig:
        """Save the form without commit, ensuring singleton behavior."""
        instance = KeyStorageConfig.get_or_create_default()
        instance.storage_type = self.cleaned_data['storage_type']
        return instance

class PKCS11ConfigForm(forms.Form):
    """Form for configuring PKCS#11 settings including HSM PIN and token information."""

    HSM_TYPE_CHOICES: ClassVar[list[tuple[str, Any]]] = [
        ('softhsm', _('SoftHSM')),
        ('physical', _('Physical HSM')),
    ]

    hsm_type = forms.ChoiceField(
        choices=HSM_TYPE_CHOICES,
        initial='softhsm',
        widget=forms.RadioSelect,
        label=_('HSM Type'),
        help_text=_('Select the type of HSM to configure.')
    )

    label = forms.CharField(
        label=_('Token Label'),
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text=_('Unique label for the PKCS#11 token'),
        required=False
    )

    slot = forms.IntegerField(
        label=_('Slot Number'),
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text=_('Slot number where the token is located'),
        min_value=0,
        required=False
    )

    module_path = forms.CharField(
        label=_('Module Path'),
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        help_text=_('Path to the PKCS#11 module library file'),
        initial='/usr/lib/libpkcs11-proxy.so',
        required=False
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the PKCS11ConfigForm with existing token data if available."""
        super().__init__(*args, **kwargs)

        try:
            token = PKCS11Token.objects.first()
            if token:
                self.fields['label'].initial = token.label
                self.fields['slot'].initial = token.slot
                self.fields['module_path'].initial = token.module_path
        except PKCS11Token.DoesNotExist:
            pass

    def clean(self) -> dict[str, Any]:
        """Custom validation for the form."""
        cleaned_data: dict[str, Any] = super().clean() or {}
        hsm_type = cleaned_data.get('hsm_type')

        if hsm_type == 'softhsm':
            cleaned_data['label'] = 'Trustpoint-SoftHSM'
            cleaned_data['slot'] = 0
            cleaned_data['module_path'] = '/usr/lib/libpkcs11-proxy.so'
        elif hsm_type == 'physical':
            raise forms.ValidationError(_('Physical HSM is not yet supported.'))

        return cleaned_data

    def clean_label(self) -> str:
        """Validate that label is unique, excluding current token if updating."""
        hsm_type = self.data.get('hsm_type')
        if hsm_type == 'softhsm':
            return 'Trustpoint-SoftHSM'

        label = self.cleaned_data.get('label', '')
        existing = PKCS11Token.objects.filter(label=label)

        current_token = PKCS11Token.objects.first()
        if current_token:
            existing = existing.exclude(pk=current_token.pk)

        if existing.exists():
            raise forms.ValidationError(_('A token with this label already exists.'))

        return str(label)

    def save_token_config(self) -> PKCS11Token:
        """Save or update token configuration."""
        data = self.cleaned_data
        token, created = PKCS11Token.objects.get_or_create(
            label=data['label'],
            defaults={
                'hsm_type': data['hsm_type'],
                'slot': data['slot'],
                'module_path': data['module_path'],
            }
        )

        if not created:
            for field, value in data.items():
                if field != 'label':
                    setattr(token, field, value)
            token.save()
        return token

class LoggingConfigForm(forms.Form):
    """Form for managing logging configuration."""

    LOG_LEVELS: ClassVar[list[tuple[str, str]]] = [
        ('DEBUG', 'DEBUG'),
        ('INFO', 'INFO'),
        ('WARNING', 'WARNING'),
        ('ERROR', 'ERROR'),
        ('CRITICAL', 'CRITICAL'),
    ]

    loglevel = forms.ChoiceField(
        label=_('Log Level'),
        choices=LOG_LEVELS,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    def save(self) -> None:
        """Save the logging configuration."""
        level = self.cleaned_data['loglevel']
        logger = logging.getLogger()
        logger.setLevel(getattr(logging, level))
        LoggingConfig.objects.update_or_create(
            id=1,
            defaults={'log_level': level}
        )

class InternationalizationConfigForm(forms.Form):
    """Form for managing internationalization configuration."""

    DATE_FORMATS: ClassVar[list[tuple[str, str]]] = [
        ('0', 'dd/MM/yyyy HH:mm'),
        ('1', 'MM/dd/yyyy HH:mm'),
        ('2', 'dd MMM yyyy HH:mm'),
        ('3', 'dd MMM yyyy hh:mm a'),
        ('4', 'dd MMMM yyyy HH:mm:ss'),
        ('5', 'dd MMMM yyyy hh:mm:ss a'),
        ('6', 'yyyy-MM-dd HH:mm:ss'),
        ('7', "yyyy-MM-dd'T'HH:mm:ss"),
    ]

    TIMEZONES: ClassVar[list[tuple[str, str]]] = sorted(
        (tz, tz) for tz in available_timezones()
    )

    date_format = forms.ChoiceField(
        label=_('Date Format'),
        choices=DATE_FORMATS,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    language = forms.ChoiceField(
        label=_('System Language'),
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    timezone = forms.ChoiceField(
        label=_('Timezone'),
        choices=TIMEZONES,
        widget=forms.Select(attrs={'class': 'form-select'}),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)

        language_field = self.fields['language']
        if isinstance(language_field, forms.ChoiceField):
            language_field.choices = settings.LANGUAGES

    def save(self) -> None:
        """Save the internationalization configuration."""
        InternationalizationConfig.objects.update_or_create(
            id=1,
            defaults={
                'date_format': self.cleaned_data['date_format'],
                'language': self.cleaned_data['language'],
                'timezone': self.cleaned_data['timezone'],
            }
        )
