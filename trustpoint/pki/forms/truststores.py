"""Django forms for truststore configuration and management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NoReturn, cast

from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
)

from pki.models.certificate import CertificateModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from util.field import UniqueNameValidator, get_certificate_name

if TYPE_CHECKING:
    from cryptography import x509


class TruststoreAddForm(forms.Form):
    """Form for adding a new truststore.

    This form handles the creation of a truststore by validating the unique name,
    intended usage, and uploaded file. It ensures the unique name is not already
    used and validates the truststore file content before saving.

    Attributes:
        unique_name (CharField): A unique name for the truststore.
        intended_usage (ChoiceField): Specifies the intended usage of the truststore.
        trust_store_file (FileField): The PEM or PKCS#7 file to be uploaded.
    """

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    intended_usage = forms.ChoiceField(
        choices=TruststoreModel.IntendedUsage,
        label=_('Intended Usage'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True,
    )

    trust_store_file = forms.FileField(label=_('PEM, DER, or PKCS#7 File'), required=True)

    def clean_unique_name(self) -> str:
        """Validates the uniqueness of the truststore name.

        Raises:
            ValidationError: If the name is already used by an existing truststore.
        """
        unique_name = self.cleaned_data['unique_name']
        if TruststoreModel.objects.filter(unique_name=unique_name).exists():
            error_message = 'Truststore with the provided name already exists.'
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
        """Cleans and validates the form data.

        Ensures the uploaded file can be read and validates the unique name
        and intended usage fields. If validation passes, initializes and saves
        the truststore.

        Raises:
            ValidationError: If the truststore file cannot be read, the unique name
            is not unique, or an unexpected error occurs during initialization.
        """
        cleaned_data = cast('dict[str, Any]', super().clean())
        unique_name = cleaned_data.get('unique_name')
        intended_usage = str(cleaned_data.get('intended_usage'))


        trust_store_file = cleaned_data.get('trust_store_file')
        if trust_store_file is None:
            self._raise_validation_error('Truststore file is required.')

        try:
            trust_store_file = cast('bytes', trust_store_file.read())
        except (OSError, AttributeError) as original_exception:
            error_message = _(
                'Unexpected error occurred while trying to get file contents. Please see logs for further details.'
            )
            raise ValidationError(error_message, code='unexpected-error') from original_exception

        try:
            certificate_collection_serializer = CertificateCollectionSerializer.from_bytes(trust_store_file)
        except Exception:  # noqa: BLE001
            # Try parsing as a single certificate (DER or PEM)
            try:
                certificate_serializer = CertificateSerializer.from_bytes(trust_store_file)
                der_bytes = certificate_serializer.as_der()
                certificate_collection_serializer = CertificateCollectionSerializer.from_list_of_der([der_bytes])
            except Exception as exception:
                error_message = _('Unable to process the Truststore. May be malformed / corrupted.')
                raise ValidationError(error_message) from exception

        try:
            certs = certificate_collection_serializer.as_crypto()
            if not unique_name:
                unique_name = get_certificate_name(certs[0])

            if TruststoreModel.objects.filter(unique_name=unique_name).exists():
                self._raise_validation_error('Truststore with the provided name already exists.')

            trust_store_model = self.save_trust_store(
                unique_name=unique_name,
                intended_usage=TruststoreModel.IntendedUsage(int(intended_usage)),
                certificates=certs,
            )
        except Exception:  # noqa: BLE001
            self._raise_validation_error('Failed to save the Truststore.')

        self.cleaned_data['truststore'] = trust_store_model

    @staticmethod
    def save_trust_store(
        unique_name: str, intended_usage: TruststoreModel.IntendedUsage, certificates: list[x509.Certificate]
    ) -> TruststoreModel:
        """Save all certificates of a truststore."""
        saved_certs: list[CertificateModel] = []

        for certificate in certificates:
            sha256_fingerprint = certificate.fingerprint(algorithm=hashes.SHA256()).hex().upper()
            try:
                saved_certs.append(CertificateModel.objects.get(sha256_fingerprint=sha256_fingerprint))
            except CertificateModel.DoesNotExist:
                saved_certs.append(CertificateModel.save_certificate(certificate))

        trust_store_model = TruststoreModel(unique_name=unique_name, intended_usage=intended_usage)
        trust_store_model.save()

        for number, certificate_model in enumerate(saved_certs):
            trust_store_order_model = TruststoreOrderModel()
            trust_store_order_model.order = number
            trust_store_order_model.certificate = certificate_model
            trust_store_order_model.trust_store = trust_store_model
            trust_store_order_model.save()

        return trust_store_model


class TruststoreDownloadForm(forms.Form):
    """Form for downloading truststores in various formats.

    This form provides options to customize the download of truststores, allowing
    users to specify the container type, inclusion of certificate chains, and
    the file format. It ensures flexibility in exporting truststores for
    various use cases and environments.

    Attributes:
        cert_file_container (ChoiceField): Specifies the container type for the truststore.
            - `single_file`: The entire truststore in a single file.
            - `zip`: Certificates as separate files in a `.zip` archive.
            - `tar_gz`: Certificates as separate files in a `.tar.gz` archive.
        cert_chain_incl (ChoiceField): Specifies whether to include certificate chains.
            - `cert_only`: Only the selected certificates.
            - `chain_incl`: Include certificate chains.
        cert_file_format (ChoiceField): Specifies the file format for the truststore.
            - `pem`: PEM format (.pem, .crt, .ca-bundle).
            - `der`: DER format (.der, .cer).
            - `pkcs7_pem`: PKCS#7 format in PEM encoding (.p7b, .p7c, .keystore).
            - `pkcs7_der`: PKCS#7 format in DER encoding (.p7b, .p7c, .keystore).
    """

    cert_file_container = forms.ChoiceField(
        label=_('Select Truststore Container Type'),
        choices=[
            ('single_file', _('Single File')),
            ('zip', _('Separate Certificate Files (as .zip file)')),
            ('tar_gz', _('Separate Certificate Files (as .tar.gz file)')),
        ],
        initial='single_file',
        required=True,
    )

    cert_chain_incl = forms.ChoiceField(
        label=_('Select Included Certificates'),
        choices=[('cert_only', _('Selected certificates only')), ('chain_incl', _('Include certificate chains'))],
        initial='selected_cert_only',
        required=True,
    )

    cert_file_format = forms.ChoiceField(
        label=_('Select Truststore File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)')),
        ],
        initial='pem',
        required=True,
    )
