"""Django forms for owner credential management."""

from __future__ import annotations

from typing import NoReturn

from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from pki.models import OwnerCredentialModel
from pki.models.certificate import CertificateModel
from trustpoint.logger import LoggerMixin
from util.field import UniqueNameValidator, get_certificate_name


class OwnerCredentialFileImportForm(LoggerMixin, forms.Form):
    """Form for importing an DevOwnerID using separate files.

    This form allows the user to upload a private key file, its password (optional),
    an DevOwnerID certificate file, and an optional certificate chain. The form
    validates the uploaded files, ensuring they are correctly formatted and within
    size limits.

    Attributes:
        unique_name (CharField): A unique name for the Owner Credential.
        private_key_file (FileField): The private key file (.key, .pem).
        private_key_file_password (CharField): An optional password for the private key.
        owner_certificate (FileField): The DevOwnerID certificate file (.cer, .der, .pem, .p7b, .p7c).
        owner_certificate_chain (FileField): An optional certificate chain file.
    """

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )
    certificate = forms.FileField(label=_('DevOwnerID Certificate (.cer, .der, .pem, .p7b, .p7c)'), required=True)
    certificate_chain = forms.FileField(label=_('[Optional] Certificate Chain (.pem, .p7b, .p7c).'), required=False)
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
            self._raise_validation_error(err_msg)

        try:
            return PrivateKeySerializer.from_bytes(private_key_file.read(), private_key_file_password)
        except Exception:  # noqa: BLE001
            err_msg = 'Failed to parse the private key file. Either wrong password or file corrupted.'
            self._raise_validation_error(err_msg)

    def clean_certificate(self) -> CertificateSerializer:
        """Validates and parses the uploaded certificate file.

        This method ensures the provided certificate file is valid and
        not already associated with an existing DevOwnerID in the database. If the
        file is too large, corrupted, or already in use, a validation error is raised.

        Returns:
            CertificateSerializer: A serializer containing the parsed certificate.

        Raises:
            ValidationError: If the file is missing, too large, corrupted, or already
            associated with an existing Issuing CA.
        """
        certificate = self.cleaned_data['certificate']

        if not certificate:
            err_msg = 'No certificate file was uploaded.'
            raise forms.ValidationError(err_msg)

        # max size: 64 kiB
        max_size = 1024 * 64
        if certificate.size > max_size:
            err_msg = 'Certificate file is too large, max. 64 kiB.'
            raise ValidationError(err_msg)

        try:
            certificate_serializer = CertificateSerializer.from_bytes(certificate.read())
        except Exception:  # noqa: BLE001
            err_msg = 'Failed to parse the certificate. Seems to be corrupted.'
            self._raise_validation_error(err_msg)

        certificate_in_db = CertificateModel.get_cert_by_sha256_fingerprint(
            certificate_serializer.as_crypto().fingerprint(algorithm=hashes.SHA256()).hex()
        )
        if certificate_in_db:
            credential_qs = OwnerCredentialModel.objects.filter(credential__certificate=certificate_in_db)
            if credential_qs.exists():
                credential_in_db = credential_qs[0]
                err_msg = (
                    f'Owner Credential {credential_in_db.unique_name} is already configured '
                    'with the same DevOwnerID.'
                )
                raise ValidationError(err_msg)

        return certificate_serializer

    def clean_certificate_chain(self) -> None | CertificateCollectionSerializer:
        """Validates and parses the uploaded certificate chain file.

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
        ca_certificate_chain = self.cleaned_data['certificate_chain']

        if ca_certificate_chain:
            try:
                return CertificateCollectionSerializer.from_bytes(ca_certificate_chain.read())
            except Exception as exception:
                err_msg = _('Failed to parse the certificate chain. Seems to be corrupted.')
                raise ValidationError(err_msg) from exception

        return None

    def _raise_validation_error(self, message: str) -> NoReturn:
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
        are valid. It also initializes and saves the OwnerCredential configuration
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
            certificate_serializer = cleaned_data.get('certificate')
            certificate_chain_serializer = (
                cleaned_data.get('certificate_chain') if cleaned_data.get('certificate_chain') else None
            )

            if not private_key_serializer or not certificate_serializer:
                return

            if not unique_name:
                name_from_cert = get_certificate_name(certificate_serializer.as_crypto())
                if not name_from_cert:
                    return
                unique_name = name_from_cert

            if OwnerCredentialModel.objects.filter(unique_name=unique_name).exists():
                error_message = 'Owner Credential with the provided name already exists.'
                self._raise_validation_error(error_message)

            cleaned_data['unique_name'] = unique_name
            self.cleaned_data = cleaned_data

            credential_serializer = CredentialSerializer.from_serializers(
                private_key_serializer=private_key_serializer,
                certificate_serializer=certificate_serializer,
                certificate_collection_serializer=certificate_chain_serializer
            )

            OwnerCredentialModel.create_new_owner_credential(
                unique_name=unique_name,
                credential_serializer=credential_serializer,
            )
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception
