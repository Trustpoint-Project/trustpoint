# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Contains Logic for Form on Add/Edit Signer Page."""

from typing import Any, ClassVar, NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeyLocation,
    PrivateKeyReference,
    PrivateKeySerializer,
)

from crypto.application.capabilities import get_active_backend_capability_report
from crypto.domain.specs import KeySpec
from crypto.runtime import configured_private_key_location
from pki.forms.credentials import parse_private_key_upload
from pki.key_types import SIGNER_KEY_TYPE_CHOICES, key_spec_for_key_type
from pki.models.certificate import CertificateModel
from pki.services.key_generation import supported_key_type_choices
from signer.models import SignerModel
from trustpoint.logger import LoggerMixin
from util.field import UniqueNameValidator, get_certificate_name


def get_private_key_location_from_config() -> PrivateKeyLocation:
    """Determine the private-key location used by legacy signer imports."""
    return configured_private_key_location()


def validate_signing_certificate(cert_crypto: x509.Certificate | None) -> None:
    """Validate that a certificate can be used for signing."""
    if cert_crypto is None:
        msg = 'Certificate is missing from credential serializer.'
        raise ValidationError(msg)

    try:
        key_usage_ext = cert_crypto.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound as exc:
        msg = 'The provided certificate does not have a KeyUsage extension and cannot be used for signing.'
        raise ValidationError(msg) from exc

    if not key_usage_ext.value.digital_signature:
        msg = 'The provided certificate does not have digitalSignature key usage and cannot be used for signing.'
        raise ValidationError(msg)


class SignerAddMethodSelectForm(forms.Form):
    """Form for selecting the method to add a Signer."""

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('generate', _('Generate new Signer with configured crypto backend')),
            ('local_file_import', _('Import a new Signer from file')),
        ],
        initial='generate',
        required=True,
    )


class SignerGenerateForm(LoggerMixin, forms.Form):
    """Form for generating a backend-managed signer."""

    KEY_TYPE_CHOICES: ClassVar[list[tuple[str, str]]] = [
        (value, _(label)) for value, label in SIGNER_KEY_TYPE_CHOICES
    ]

    unique_name = forms.CharField(
        max_length=256,
        label=_('Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=True,
        validators=[UniqueNameValidator()],
    )
    key_type = forms.ChoiceField(label=_('Key Type'), choices=KEY_TYPE_CHOICES, required=True)

    created_signer: SignerModel

    @staticmethod
    def _key_spec_for_key_type(key_type: str) -> KeySpec:
        """Map the existing signer form values through the shared catalog."""
        if key_type not in dict(SIGNER_KEY_TYPE_CHOICES):
            msg = f'Unsupported signer key type {key_type!r}.'
            raise ValueError(msg)
        return key_spec_for_key_type(key_type)

    @classmethod
    def supported_key_type_choices(cls) -> list[tuple[str, str]]:
        """Return signer key choices supported by the active backend."""
        return supported_key_type_choices(cls.KEY_TYPE_CHOICES, report=get_active_backend_capability_report())

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form with backend-supported key choices."""
        super().__init__(*args, **kwargs)
        cast('forms.ChoiceField', self.fields['key_type']).choices = self.supported_key_type_choices()

    def clean_unique_name(self) -> str:
        """Validate unique signer names."""
        unique_name = cast('str', self.cleaned_data['unique_name']).strip()
        if SignerModel.objects.filter(unique_name=unique_name).exists():
            error_message = _('Unique name is already taken. Choose another one.')
            raise ValidationError(error_message)
        return unique_name

    def clean(self) -> dict[str, Any]:
        """Validate backend key support."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        key_type = cleaned_data.get('key_type')
        supported_key_types = {value for value, _label in self.supported_key_type_choices()}
        if not supported_key_types:
            self.add_error('key_type', _('The active crypto backend cannot generate any supported signer key.'))
        elif key_type not in supported_key_types:
            self.add_error('key_type', _('The active crypto backend does not support this signer key type.'))
        return cleaned_data

    def save(self) -> SignerModel:
        """Generate and persist the backend-managed signer."""
        self.created_signer = SignerModel.create_backend_managed_signer(
            unique_name=self.cleaned_data['unique_name'],
            key_spec=self._key_spec_for_key_type(self.cleaned_data['key_type']),
        )
        return self.created_signer


class SignerAddFileTypeSelectForm(forms.Form):
    """Form for selecting the file type when importing a Signer."""

    method_select = forms.ChoiceField(
        label=_('File Type'),
        choices=[
            ('pkcs_12', _('PKCS#12')),
            ('other', _('PEM, PKCS#1, PKCS#7, PKCS#8')),
        ],
        initial='pkcs_12',
        required=True,
    )

class SignerAddFileImportPkcs12Form(LoggerMixin, forms.Form):
    """Form for importing an Signer using a PKCS#12 file."""

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    pkcs12_file = forms.FileField(label=_('PKCS#12 File (.p12, .pfx)'), required=True)
    pkcs12_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code  # noqa: FIX004
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] PKCS#12 password'),
        required=False,
    )

    def clean_unique_name(self) -> str:
        """Validates the unique name to ensure it is not already in use."""
        unique_name = self.cleaned_data['unique_name']
        if SignerModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Unique name is already taken. Choose another one.'
            raise ValidationError(error_message)
        return cast('str', unique_name)

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Helper method to raise a ValidationError with a given message."""
        raise ValidationError(message)

    def clean(self) -> None:
        """Cleans and validates the entire form."""
        cleaned_data = super().clean()
        if not cleaned_data:
            self._raise_validation_error('No data was provided.')

        pkcs12_raw, pkcs12_password = self._validate_pkcs12_file(cleaned_data)
        credential_serializer = self._process_pkcs12_file(pkcs12_raw, pkcs12_password, cleaned_data.get('unique_name'))
        if credential_serializer.certificate is None:
            self._raise_validation_error('No certificate found in PKCS#12 file.')
        self._validate_certificate(credential_serializer.certificate)
        self._save_signer(cleaned_data, credential_serializer)

    def _validate_pkcs12_file(self, cleaned_data: dict[str, Any]) -> tuple[bytes, bytes | None]:
        """Validates and reads the PKCS#12 file."""
        pkcs12_file = cleaned_data.get('pkcs12_file')
        if pkcs12_file is None:
            self._raise_validation_error('PKCS#12 file is required.')

        try:
            pkcs12_raw = pkcs12_file.read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
            if pkcs12_password:
                pkcs12_password = pkcs12_password.encode()
        except (OSError, AttributeError, UnicodeEncodeError) as e:
            raise ValidationError(_('Error reading PKCS#12 file or password.')) from e

        return pkcs12_raw, pkcs12_password

    def _process_pkcs12_file(
        self,
        pkcs12_raw: bytes,
        pkcs12_password: bytes | None,
        unique_name: str | None
    ) -> CredentialSerializer:
        """Processes the PKCS#12 file and returns a credential serializer."""
        try:
            credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, pkcs12_password)
            if credential_serializer.private_key is None:
                self._raise_validation_error('Private key is missing from credential serializer.')

            private_key_location = get_private_key_location_from_config()
            credential_serializer.private_key_reference = PrivateKeyReference.from_private_key(
                private_key=credential_serializer.private_key,
                key_label=unique_name,
                location=private_key_location,
            )
        except Exception as e:
            raise ValidationError(_('Failed to parse PKCS#12 file.')) from e

        return credential_serializer

    def _validate_certificate(self, cert_crypto: x509.Certificate) -> None:
        """Validates the certificate for required extensions."""
        validate_signing_certificate(cert_crypto)

    def _save_signer(self, cleaned_data: dict[str, Any], credential_serializer: CredentialSerializer) -> None:
        """Saves the signer to the database."""
        if credential_serializer.certificate is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        unique_name = cleaned_data.get('unique_name') or get_certificate_name(credential_serializer.certificate)

        if SignerModel.objects.filter(unique_name=unique_name).exists():
            self._raise_validation_error('Unique name is already taken. Choose another one.')

        try:
            self.created_signer = SignerModel.create_new_signer(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
            )
        except Exception:  # noqa: BLE001
            self._raise_validation_error('Failed to process the Signer. Please see logs for further details.')


class SignerAddFileImportSeparateFilesForm(LoggerMixin, forms.Form):
    """Form for importing a Signer using separate files."""

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )
    signer_certificate = forms.FileField(label=_('Signer Certificate (.cer, .der, .pem, .p7b, .p7c)'), required=True)
    signer_certificate_chain = forms.FileField(
        label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c).'), required=False
    )
    private_key_file = forms.FileField(label=_('Private Key File (.key, .pem)'), required=True)
    private_key_file_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code  # noqa: FIX004
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password'),
        required=False,
    )

    def clean_private_key_file(self) -> PrivateKeySerializer:
        """Validate and parse the uploaded private key file."""
        return parse_private_key_upload(
            self.cleaned_data.get('private_key_file'), self.data.get('private_key_file_password') or None
        )

    def clean_signer_certificate(self) -> CertificateSerializer:
        """Validates and parses the uploaded signer certificate file."""
        signer_certificate = self.cleaned_data['signer_certificate']

        if not signer_certificate:
            err_msg = 'No signer certificate file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if signer_certificate.size > max_size:
            err_msg = 'Signer certificate file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        try:
            certificate_serializer = CertificateSerializer.from_bytes(signer_certificate.read())
        except Exception:  # noqa: BLE001
            err_msg = 'Failed to parse the signer certificate. Seems to be corrupted.'
            self._raise_validation_error(err_msg)

        cert_crypto = certificate_serializer.as_crypto()
        validate_signing_certificate(cert_crypto)

        certificate_in_db = CertificateModel.get_cert_by_sha256_fingerprint(
            certificate_serializer.as_crypto().fingerprint(algorithm=hashes.SHA256()).hex()
        )
        if certificate_in_db:
            issuing_ca_qs = SignerModel.objects.filter(credential__certificate=certificate_in_db)
            if issuing_ca_qs.exists():
                issuing_ca_in_db = issuing_ca_qs[0]
                err_msg = (
                    f'Signer {issuing_ca_in_db.unique_name} is already configured '
                    'with the same Signer certificate.'
                )
                raise ValidationError(err_msg)

        return certificate_serializer

    def clean_signer_certificate_chain(self) -> CertificateCollectionSerializer | None:
        """Validates and parses the uploaded signer certificate chain file."""
        signer_certificate_chain = self.cleaned_data['signer_certificate_chain']

        if signer_certificate_chain:
            try:
                return CertificateCollectionSerializer.from_bytes(signer_certificate_chain.read())
            except Exception as exception:
                err_msg = _('Failed to parse the signer certificate chain. Seems to be corrupted.')
                raise ValidationError(err_msg) from exception

        return None

    def _raise_validation_error(self, message: str) -> None:
        """Helper method to raise a ValidationError with a given message."""
        raise ValidationError(message)

    def clean(self) -> None:
        """Cleans and validates the form data."""
        try:
            cleaned_data = super().clean()
            if not cleaned_data:
                return

            self._validate_required_fields(cleaned_data)
            credential_serializer = self._create_credential_serializer(cleaned_data)
            self._validate_credential_serializer(credential_serializer)
            self._save_signer(cleaned_data, credential_serializer)
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception

    def _validate_required_fields(self, cleaned_data: dict[str, Any]) -> None:
        """Validates required fields."""
        if not cleaned_data.get('private_key_file') or not cleaned_data.get('signer_certificate'):
            return

    def _create_credential_serializer(self, cleaned_data: dict[str, Any]) -> CredentialSerializer:
        """Creates a credential serializer from the cleaned data."""
        private_key_serializer = cleaned_data.get('private_key_file')
        signer_certificate_serializer = cleaned_data.get('signer_certificate')
        signer_certificate_chain_serializer = cleaned_data.get('signer_certificate_chain')

        return CredentialSerializer.from_serializers(
            private_key_serializer=private_key_serializer,
            certificate_serializer=signer_certificate_serializer,
            certificate_collection_serializer=signer_certificate_chain_serializer,
        )

    def _validate_credential_serializer(self, credential_serializer: CredentialSerializer) -> None:
        """Validates the credential serializer."""
        pk = credential_serializer.private_key
        cert = credential_serializer.certificate

        if cert is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        if pk is None:
            self._raise_validation_error('Private key is missing from credential serializer.')
        if pk.public_key() != cert.public_key():  # type: ignore[union-attr]
            self._raise_validation_error('The provided private key does not match the Signer certificate.')

        private_key_location = get_private_key_location_from_config()
        credential_serializer.private_key_reference = PrivateKeyReference.from_private_key(
            private_key=pk,  # type: ignore[arg-type]
            key_label=None,
            location=private_key_location,
        )

    def _save_signer(self, cleaned_data: dict[str, Any], credential_serializer: CredentialSerializer) -> None:
        """Saves the signer to the database."""
        if credential_serializer.certificate is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        unique_name = cleaned_data.get('unique_name') or get_certificate_name(credential_serializer.certificate)  # type: ignore[arg-type]

        if SignerModel.objects.filter(unique_name=unique_name).exists():
            self._raise_validation_error('Unique name is already taken. Choose another one.')

        self.created_signer = SignerModel.create_new_signer(
            unique_name=unique_name,
            credential_serializer=credential_serializer,
        )


class SignHashForm(LoggerMixin, forms.Form):
    """Form for signing a hash value with a selected signer."""

    signer = forms.ModelChoiceField(
        queryset=SignerModel.objects.filter(is_active=True),
        label=_('Select Signer'),
        required=True,
        help_text=_("The hash algorithm used for signing will be determined by the selected signer's certificate."),
        empty_label=_('Select a signer...'),
    )

    hash_value = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': _('Enter hash value in hexadecimal format')}),
        label=_('Hash Value'),
        required=True,
        help_text=_('Paste the hash value (hexadecimal format, e.g., a1b2c3d4...)'),
    )

    def clean(self) -> dict[str, Any]:
        """Validate the hash value format based on the selected signer's hash algorithm."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        signer = cleaned_data.get('signer')
        hash_value = cleaned_data.get('hash_value', '').strip()

        if not signer or not hash_value:
            return cleaned_data

        hash_value = hash_value.replace(' ', '').replace('\n', '').replace('\r', '')
        hash_value = hash_value.replace(':', '').replace('-', '')

        if not hash_value:
            raise ValidationError({'hash_value': _('Hash value cannot be empty')})

        try:
            bytes.fromhex(hash_value)
        except ValueError as e:
            raise ValidationError({
                'hash_value': _('Invalid hash format. Please provide a valid hexadecimal string.')
            }) from e

        hash_algorithm = signer.hash_algorithm
        expected_lengths = {
            'SHA1': 40,      # 160 bits = 20 bytes = 40 hex chars
            'SHA224': 56,    # 224 bits = 28 bytes = 56 hex chars
            'SHA256': 64,    # 256 bits = 32 bytes = 64 hex chars
            'SHA384': 96,    # 384 bits = 48 bytes = 96 hex chars
            'SHA512': 128,   # 512 bits = 64 bytes = 128 hex chars
        }

        expected_length = expected_lengths.get(hash_algorithm)
        if expected_length and len(hash_value) != expected_length:
            raise ValidationError({
                'hash_value': _('Hash value length mismatch. The selected signer uses %(algorithm)s '
                               'which expects %(expected)d hexadecimal characters, but got %(actual)d.') % {
                    'algorithm': hash_algorithm,
                    'expected': expected_length,
                    'actual': len(hash_value)
                }
            })

        cleaned_data['hash_value'] = hash_value.lower()
        return cleaned_data
