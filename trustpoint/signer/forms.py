"""Contains Logic for Form on Add/Edit Signer Page."""

from typing import NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from management.models import KeyStorageConfig
from pki.models.certificate import CertificateModel
from signer.models import SignerModel
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeyLocation,
    PrivateKeyReference,
    PrivateKeySerializer,
)
from util.field import UniqueNameValidator, get_certificate_name

from trustpoint.logger import LoggerMixin


def get_private_key_location_from_config() -> PrivateKeyLocation:
    """Determine the appropriate PrivateKeyLocation based on KeyStorageConfig."""
    try:
        storage_config = KeyStorageConfig.get_config()
        if storage_config.storage_type in [
            KeyStorageConfig.StorageType.SOFTHSM,
            KeyStorageConfig.StorageType.PHYSICAL_HSM
        ]:
            return PrivateKeyLocation.HSM_PROVIDED
    except KeyStorageConfig.DoesNotExist:
        pass

    return PrivateKeyLocation.SOFTWARE


class SignerAddMethodSelectForm(forms.Form):
    """Form for selecting the method to add a Signer."""

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('local_file_import', _('Import a new Signer from file')),
        ],
        initial='local_file_import',
        required=True,
    )

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
        if not cleaned_data:  # only for typing, cleaned_data should always be a dict, but not entirely sure
            exc_msg = 'No data was provided.'
            raise ValidationError(exc_msg)
        unique_name = cleaned_data.get('unique_name')

        pkcs12_file = cleaned_data.get('pkcs12_file')
        if pkcs12_file is None:
            self._raise_validation_error('PKCS#12 file is required.')

        try:
            pkcs12_raw = pkcs12_file.read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
        except (OSError, AttributeError) as original_exception:
            # These exceptions are likely to occur if the file cannot be read or is missing attributes.
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.'
            )
            raise ValidationError(error_message, code='unexpected-error') from original_exception

        if pkcs12_password:
            try:
                pkcs12_password = pkcs12_password.encode()
            except Exception as original_exception:
                error_message = _('The PKCS#12 password contains invalid data, that cannot be encoded in UTF-8.')
                raise ValidationError(error_message) from original_exception
        else:
            pkcs12_password = None

        try:
            credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, pkcs12_password)
            if credential_serializer.private_key is None:
                self._raise_validation_error('Private key is missing from credential serializer.')

            # Determine the appropriate private key location based on system configuration
            private_key_location = get_private_key_location_from_config()

            credential_serializer.private_key_reference = (
                PrivateKeyReference.from_private_key(
                    private_key=credential_serializer.private_key,
                    key_label=unique_name,
                    location=private_key_location
                )
            )
        except Exception as exception:
            err_msg = _('Failed to parse and load the uploaded file. Either wrong password or corrupted file.')
            raise ValidationError(err_msg) from exception

        cert_crypto = credential_serializer.certificate
        if cert_crypto is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')

        try:
            key_usage_ext = cert_crypto.extensions.get_extension_for_class(x509.KeyUsage)
            if not key_usage_ext.value.digital_signature:
                self._raise_validation_error(
                    'The provided certificate does not have digitalSignature key usage and cannot be used for signing.'
                )
        except x509.ExtensionNotFound:
            self._raise_validation_error(
                'The provided certificate does not have a KeyUsage extension and cannot be used for signing.'
            )

        try:
            if not unique_name:
                unique_name = get_certificate_name(cert_crypto)

            if SignerModel.objects.filter(unique_name=unique_name).exists():
                self._raise_validation_error('Unique name is already taken. Choose another one.')

            SignerModel.create_new_signer(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
            )
        except ValidationError:
            raise
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
        """Validates and parses the uploaded private key file."""
        private_key_file = self.cleaned_data.get('private_key_file')
        private_key_file_password = (
            self.data.get('private_key_file_password') if self.data.get('private_key_file_password') else None
        )

        if not private_key_file:
            err_msg = 'No private key file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if private_key_file.size > max_size:
            err_msg = 'Private key file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        if private_key_file_password:
            try:
                private_key_file_password = private_key_file_password.encode('utf-8')
            except Exception as original_exception:
                err_msg = 'The private key password contains invalid data that cannot be encoded in UTF-8.'
                raise ValidationError(err_msg) from original_exception
        else:
            private_key_file_password = None

        try:
            private_key_file = PrivateKeySerializer.from_bytes(private_key_file.read(), private_key_file_password)
        except Exception:  # noqa: BLE001
            err_msg = 'Failed to parse the private key file. Either wrong password or file corrupted.'
            self._raise_validation_error(err_msg)
        return private_key_file

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

        try:
            key_usage_ext = cert_crypto.extensions.get_extension_for_class(x509.KeyUsage)
            if not key_usage_ext.value.digital_signature:
                err_msg = (
                    'The provided certificate does not have digitalSignature key usage '
                    'and cannot be used for signing.'
                )
                self._raise_validation_error(err_msg)
        except x509.ExtensionNotFound:
            err_msg = 'The provided certificate does not have a KeyUsage extension and cannot be used for signing.'
            self._raise_validation_error(err_msg)

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

    def clean_signer_certificate_chain(self) -> None | CertificateCollectionSerializer:
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
            unique_name = cleaned_data.get('unique_name')
            private_key_serializer = cleaned_data.get('private_key_file')
            signer_certificate_serializer = cleaned_data.get('signer_certificate')
            signer_certificate_chain_serializer = (
                cleaned_data.get('signer_certificate_chain') if cleaned_data.get('signer_certificate_chain') else None
            )

            if not private_key_serializer or not signer_certificate_serializer:
                return

            credential_serializer = CredentialSerializer.from_serializers(
                private_key_serializer=private_key_serializer,
                certificate_serializer=signer_certificate_serializer,
                certificate_collection_serializer=signer_certificate_chain_serializer,
            )

            pk = credential_serializer.private_key
            cert = credential_serializer.certificate
            if cert is None:
                self._raise_validation_error('Certificate is missing from credential serializer.')
                return
            if pk is None:
                self._raise_validation_error('Private key is missing from credential serializer.')
                return
            if pk.public_key() != cert.public_key():
                self._raise_validation_error('The provided private key does not match the Signer certificate.')

            if credential_serializer and credential_serializer.private_key is None:
                self._raise_validation_error('Private key is missing from credential serializer.')

            private_key_location = get_private_key_location_from_config()

            credential_serializer.private_key_reference = (
                PrivateKeyReference.from_private_key(
                    private_key=pk,
                    key_label=unique_name,
                    location=private_key_location
                )
            )

            if not unique_name:
                unique_name = get_certificate_name(cert)

            if SignerModel.objects.filter(unique_name=unique_name).exists():
                error_message = 'Unique name is already taken. Choose another one.'
                self._raise_validation_error(error_message)

            SignerModel.create_new_signer(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
            )
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception


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

    def clean(self) -> dict[str, any]:
        """Validate the hash value format based on the selected signer's hash algorithm."""
        cleaned_data = super().clean()
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
