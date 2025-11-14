"""Contains Logic for Form on Add/Edit Signer Page."""

from typing import NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
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
        """Validates the unique name to ensure it is not already in use.

        Raises:
            ValidationError: If the unique name is already associated with an existing Issuing CA.
        """
        unique_name = self.cleaned_data['unique_name']
        if SignerModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Unique name is already taken. Choose another one.'
            raise ValidationError(error_message)
        return cast('str', unique_name)

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Helper method to raise a ValidationError with a given message.

        Args:
            message (str): The error message to be included in the ValidationError.

        Raises:
            ValidationError: Always raised with the provided message.
        """
        raise ValidationError(message)

    def clean(self) -> None:
        """Cleans and validates the entire form.

        This method performs additional validation on the cleaned data to ensure
        all required fields are valid and consistent. It checks the uploaded PKCS#12
        file and its password (if provided) and validates that the unique name
        does not conflict with existing entries. Any issues during validation
        raise appropriate errors.

        Raises:
            ValidationError: If the data is invalid, such as when the unique name
            is already taken or the PKCS#12 file cannot be read or parsed.
        """
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
            credential_serializer.private_key_reference = (
                PrivateKeyReference.from_private_key(private_key=credential_serializer.private_key,
                                                     key_label=unique_name,
                                                     location=PrivateKeyLocation.HSM_PROVIDED))
        except Exception as exception:
            err_msg = _('Failed to parse and load the uploaded file. Either wrong password or corrupted file.')
            raise ValidationError(err_msg) from exception

        cert_crypto = credential_serializer.certificate
        if cert_crypto is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        if cert_crypto.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False:
            self._raise_validation_error('The provided certificate is not a CA certificate.')

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
    ca_certificate = forms.FileField(label=_('Issuing CA Certificate (.cer, .der, .pem, .p7b, .p7c)'), required=True)
    ca_certificate_chain = forms.FileField(label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c).'), required=False)
    private_key_file = forms.FileField(label=_('Private Key File (.key, .pem)'), required=True)
    private_key_file_password = forms.CharField(
        # hack, force autocomplete off in chrome with: one-time-code  # noqa: FIX004
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] Private Key File Password'),
        required=False,
    )

    def clean_private_key_file(self) -> PrivateKeySerializer:
        """Validates and parses the uploaded private key file.

        This method checks if the private key file is provided, ensures it meets
        size constraints, and validates its contents. If a password is provided,
        it is used to decrypt the private key. Raises validation errors for missing,
        oversized, or corrupted private key files.

        Returns:
            PrivateKeySerializer: A serializer containing the parsed private key.

        Raises:
            ValidationError: If the private key file is missing, too large, or
            corrupted, or if the password is invalid or incompatible.
        """
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

    def clean_ca_certificate(self) -> CertificateSerializer:
        """Validates and parses the uploaded Issuing CA certificate file.

        This method ensures the provided Issuing CA certificate file is valid and
        not already associated with an existing Issuing CA in the database. If the
        file is too large, corrupted, or already in use, a validation error is raised.

        Returns:
            CertificateSerializer: A serializer containing the parsed certificate.

        Raises:
            ValidationError: If the file is missing, too large, corrupted, or already
            associated with an existing Issuing CA.
        """
        ca_certificate = self.cleaned_data['ca_certificate']

        if not ca_certificate:
            err_msg = 'No Issuing CA file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if ca_certificate.size > max_size:
            err_msg = 'Issuing CA file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        try:
            certificate_serializer = CertificateSerializer.from_bytes(ca_certificate.read())
        except Exception:  # noqa: BLE001
            err_msg = 'Failed to parse the Issuing CA certificate. Seems to be corrupted.'
            self._raise_validation_error(err_msg)

        cert_crypto = certificate_serializer.as_crypto()
        if cert_crypto.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False:
            err_msg = 'The provided certificate is not a CA certificate.'
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

    def clean_ca_certificate_chain(self) -> None | CertificateCollectionSerializer:
        """Validates and parses the uploaded Issuing CA certificate chain file.

        This method checks if the optional certificate chain file is provided.
        If present, it validates and attempts to parse the file into a collection
        of certificates. Raises a validation error if parsing fails or the file
        appears corrupted.

        Returns:
            CertificateCollectionSerializer: A serializer containing the parsed
            certificate chain if provided.

        Raises:
            ValidationError: If the certificate chain cannot be parsed.
        """
        ca_certificate_chain = self.cleaned_data['ca_certificate_chain']

        if ca_certificate_chain:
            try:
                return CertificateCollectionSerializer.from_bytes(ca_certificate_chain.read())
            except Exception as exception:
                err_msg = _('Failed to parse the Issuing CA certificate chain. Seems to be corrupted.')
                raise ValidationError(err_msg) from exception

        return None

    def _raise_validation_error(self, message: str) -> None:
        """Helper method to raise a ValidationError with a given message.

        Args:
            message (str): The error message to be included in the ValidationError.

        Raises:
            ValidationError: Always raised with the provided message.
        """
        raise ValidationError(message)

    def clean(self) -> None:
        """Cleans and validates the form data.

        This method performs additional validation on the provided data,
        such as ensuring the unique name, private key file, and certificates
        are valid. It also initializes and saves the issuing CA configuration
        if all checks pass.

        Raises:
            ValidationError: If the form data is invalid or there is an error during processing.
        """
        try:
            cleaned_data = super().clean()
            if not cleaned_data:
                return
            unique_name = cleaned_data.get('unique_name')
            private_key_serializer = cleaned_data.get('private_key_file')
            ca_certificate_serializer = cleaned_data.get('ca_certificate')
            ca_certificate_chain_serializer = (
                cleaned_data.get('ca_certificate_chain') if cleaned_data.get('ca_certificate_chain') else None
            )

            if not private_key_serializer or not ca_certificate_serializer:
                return

            credential_serializer = CredentialSerializer.from_serializers(
                private_key_serializer=private_key_serializer,
                certificate_serializer=ca_certificate_serializer,
                certificate_collection_serializer=ca_certificate_chain_serializer,
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

            credential_serializer.private_key_reference = (
                PrivateKeyReference.from_private_key(private_key=pk,
                                                     key_label=unique_name,
                                                     location=PrivateKeyLocation.HSM_PROVIDED))

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
