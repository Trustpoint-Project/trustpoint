"""Module for managing PKI-related forms in the Trustpoint application."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from pydantic import ValidationError as PydanticValidationError
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeyLocation,
    PrivateKeyReference,
    PrivateKeySerializer,
)

from management.models import KeyStorageConfig
from onboarding.models import NoOnboardingConfigModel, NoOnboardingPkiProtocol
from pki.models import CaModel, DevIdRegistration, OwnerCredentialModel
from pki.models.cert_profile import CertificateProfileModel
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel
from pki.util.cert_profile import CERT_PROFILE_KEYWORDS, JSONProfileVerifier
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel
from pki.util.cert_req_converter import JSONCertRequestConverter
from pki.util.x509 import CertificateGenerator
from trustpoint.logger import LoggerMixin
from util.field import UniqueNameValidator, get_certificate_name
from util.validation import ValidationError as UtilValidationError
from util.validation import validate_remote_ca_connection

if TYPE_CHECKING:
    from cryptography.x509.base import CertificateBuilder


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


def get_ca_type_from_config() -> CaModel.CaTypeChoice:
    """Determine the appropriate CA type based on KeyStorageConfig."""
    try:
        storage_config = KeyStorageConfig.get_config()
        if storage_config.storage_type in [
            KeyStorageConfig.StorageType.SOFTHSM,
            KeyStorageConfig.StorageType.PHYSICAL_HSM
        ]:
            return CaModel.CaTypeChoice.LOCAL_PKCS11
    except KeyStorageConfig.DoesNotExist:
        pass

    return CaModel.CaTypeChoice.LOCAL_UNPROTECTED


class IssuingCaImportMixin:
    """Mixin for Issuing CA import forms providing common validation and creation logic."""

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Helper method to raise a ValidationError with a given message.

        Args:
            message (str): The error message to be included in the ValidationError.

        Raises:
            ValidationError: Always raised with the provided message.
        """
        raise ValidationError(message)

    def _validate_ca_certificate(self, cert_crypto: x509.Certificate) -> None:
        """Validates that the certificate is a CA certificate with required extensions."""
        if cert_crypto.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False:
            self._raise_validation_error('The provided certificate is not a CA certificate.')
        try:
            key_usage_ext = cert_crypto.extensions.get_extension_for_class(x509.KeyUsage)
            if not key_usage_ext.value.key_cert_sign:
                self._raise_validation_error('The provided certificate must have keyCertSign usage enabled.')
            if not key_usage_ext.value.crl_sign:
                self._raise_validation_error('The provided certificate must have cRLSign usage enabled.')
        except x509.ExtensionNotFound:
            self._raise_validation_error('KeyUsage extension is required for CA certificates.')

    def _check_duplicate_issuing_ca(self, cert_crypto: x509.Certificate) -> None:
        """Checks if the certificate is already used by an existing Issuing CA."""
        certificate_in_db = CertificateModel.get_cert_by_sha256_fingerprint(
            cert_crypto.fingerprint(algorithm=hashes.SHA256()).hex()
        )
        if certificate_in_db:
            issuing_ca_qs = CaModel.objects.filter(credential__certificate=certificate_in_db)
            if issuing_ca_qs.exists():
                ca_in_db = issuing_ca_qs[0]
                err_msg = (
                    f'Issuing CA {ca_in_db.unique_name} is already configured '
                    'with the same Issuing CA certificate.'
                )
                self._raise_validation_error(err_msg)

    def _finalize_issuing_ca_creation(
        self, unique_name: str | None, cert: x509.Certificate, credential_serializer: CredentialSerializer
    ) -> None:
        """Finalizes the creation of the Issuing CA after validation."""
        if not unique_name:
            unique_name = get_certificate_name(cert)

        if CaModel.objects.filter(unique_name=unique_name).exists():
            self._raise_validation_error('Unique name is already taken. Choose another one.')

        try:
            CaModel.create_new_issuing_ca(
                credential_serializer=credential_serializer,
                ca_type=get_ca_type_from_config(),
                unique_name=unique_name,
            )
        except ValidationError:
            raise
        except Exception:  # noqa: BLE001
            self._raise_validation_error('Failed to process the Issuing CA. Please see logs for further details.')


class DevIdAddMethodSelectForm(forms.Form):
    """Form for selecting the method to add an DevID Onboarding Pattern.

    Attributes:
        method_select (ChoiceField): A dropdown to select the method for adding an Issuing CA.
            - `import_truststore`: Import a new truststore prior to configuring a new pattern.
            - `configure_pattern`: Use an existing truststore to define a new pattern.
    """

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('import_truststore', _('Import a new truststore prior to configuring a new pattern')),
            ('configure_pattern', _('Use an existing truststore to define a new pattern')),
        ],
        initial='configure_pattern',
        required=True,
    )


class DevIdRegistrationForm(forms.ModelForm[DevIdRegistration]):
    """Form to create a new DevIdRegistration."""

    class Meta:  # noqa: D106
        model = DevIdRegistration
        fields: ClassVar[list[str]] = ['unique_name', 'truststore', 'domain', 'serial_number_pattern']
        widgets: ClassVar[dict[str, Any]] = {
            'serial_number_pattern': forms.TextInput(
                attrs={
                    'placeholder': 'Enter a regex pattern for serial numbers',
                }
            ),
        }
        labels: ClassVar[dict[str, str]] = {
            'unique_name': 'Unique Name',
            'truststore': 'Associated Truststore',
            'domain': 'Associated Domain',
            'serial_number_pattern': 'Serial Number Pattern (Regex)',
        }


    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    def clean(self) -> None:
        """Cleans and validates the form data.

        Ensures the unique name is not already used if provided.

        Raises:
            ValidationError: If the unique name is not unique.
        """
        cleaned_data = super().clean()
        if cleaned_data is None:
            exc_msg = 'No data was provided.'
            raise ValidationError(exc_msg)
        unique_name = cleaned_data.get('unique_name')
        truststore_name = cleaned_data.get('truststore')

        if not unique_name and truststore_name:
            unique_name = truststore_name.unique_name
            cleaned_data['unique_name'] = unique_name

        if unique_name and DevIdRegistration.objects.filter(unique_name=unique_name).exists():
            error_message = 'DevID Registration with the provided name already exists.'
            raise ValidationError(error_message)

        self.cleaned_data = cleaned_data


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


class CertificateDownloadForm(forms.Form):
    """Form for downloading certificates in various formats.

    This form allows users to customize the download options for certificates,
    including the container type, inclusion of certificate chains, and the
    file format. It provides flexibility to download certificates in the
    desired structure and format for different use cases.

    Attributes:
        cert_file_container (ChoiceField): Specifies the container type for the downloaded certificates.
            - `single_file`: All certificates in a single file.
            - `zip`: Certificates as separate files in a `.zip` archive.
            - `tar_gz`: Certificates as separate files in a `.tar.gz` archive.
        cert_chain_incl (ChoiceField): Specifies whether to include certificate chains.
            - `cert_only`: Only the selected certificates.
            - `chain_incl`: Include certificate chains.
        cert_file_format (ChoiceField): Specifies the file format for the certificates.
            - `pem`: PEM format (.pem, .crt, .ca-bundle).
            - `der`: DER format (.der, .cer).
            - `pkcs7_pem`: PKCS#7 format in PEM encoding (.p7b, .p7c, .keystore).
            - `pkcs7_der`: PKCS#7 format in DER encoding (.p7b, .p7c, .keystore).
    """

    cert_file_container = forms.ChoiceField(
        label=_('Select Certificate Container Type'),
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
        label=_('Select Certificate File Format'),
        choices=[
            ('pem', _('PEM (.pem, .crt, .ca-bundle)')),
            ('der', _('DER (.der, .cer)')),
            ('pkcs7_pem', _('PKCS#7 (PEM) (.p7b, .p7c, .keystore)')),
            ('pkcs7_der', _('PKCS#7 (DER) (.p7b, .p7c, .keystore)')),
        ],
        initial='pem',
        required=True,
    )


class IssuingCaAddMethodSelectForm(forms.Form):
    """Form for selecting the method to add an Issuing Certificate Authority (CA).

    This form provides options to choose the method for adding a new Issuing CA.
    Users can select between importing from a file, generating a key pair and
    requesting an Issuing CA certificate, or configuring a remote Issuing CA.

    Attributes:
        method_select (ChoiceField): A dropdown to select the method for adding an Issuing CA.
            - `local_file_import`: Import a new Issuing CA from a file.
            - `local_request`: Generate a key-pair and request a certificate.
            - `remote_est`: Configure a remote Issuing CA.
    """

    method_select = forms.ChoiceField(
        label=_('Select Method'),
        choices=[
            ('local_file_import', _('Import a new Issuing CA from file')),
            ('local_request', _('Generate a key-pair and request an Issuing CA certificate')),
            ('remote_est', _('Configure a remote Issuing CA')),
        ],
        initial='local_file_import',
        required=True,
    )


class IssuingCaFileTypeSelectForm(forms.Form):
    """Form for selecting the file type when importing an Issuing CA.

    This form allows users to choose the type of file to use for importing an
    Issuing Certificate Authority (CA). Supported formats include PKCS#12 and
    other common certificate formats such as PEM, PKCS#1, PKCS#7, and PKCS#8.

    Attributes:
        method_select (ChoiceField): A dropdown to select the file type for the Issuing CA.
    """

    # TODO(AlexHx8472): do we need .jks? Java Keystore  # noqa: FIX002
    method_select = forms.ChoiceField(
        label=_('File Type'),
        choices=[
            ('pkcs_12', _('PKCS#12')),
            ('other', _('PEM, PKCS#1, PKCS#7, PKCS#8')),
        ],
        initial='pkcs_12',
        required=True,
    )


class IssuingCaAddFileImportPkcs12Form(IssuingCaImportMixin, LoggerMixin, forms.Form):
    """Form for importing an Issuing CA using a PKCS#12 file.

    This form allows the user to upload a PKCS#12 file containing the private key
    and certificate chain, along with an optional password. It validates the
    uploaded file and its contents and ensures the unique name is not already
    used by another Issuing CA.

    Attributes:
        unique_name (CharField): A unique name for the Issuing CA.
        pkcs12_file (FileField): The PKCS#12 file containing the private key and certificates.
        pkcs12_password (CharField): An optional password for the PKCS#12 file.
    """

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

    def _read_and_encode_pkcs12_file(self, cleaned_data: dict[str, Any]) -> tuple[bytes, bytes | None]:
        """Reads the PKCS#12 file and encodes the password if provided."""
        pkcs12_file = cleaned_data.get('pkcs12_file')
        if pkcs12_file is None:
            self._raise_validation_error('PKCS#12 file is required.')

        try:
            pkcs12_raw = pkcs12_file.read()
            pkcs12_password = cleaned_data.get('pkcs12_password')
        except (OSError, AttributeError) as original_exception:
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

        return pkcs12_raw, pkcs12_password

    def _parse_and_prepare_credential(
        self, pkcs12_raw: bytes, pkcs12_password: bytes | None, unique_name: str | None
    ) -> CredentialSerializer:
        """Parses the PKCS#12 file and prepares the credential serializer."""
        try:
            credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, pkcs12_password)
            if credential_serializer.private_key is None:
                self._raise_validation_error('Private key is missing from credential serializer.')
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

        return credential_serializer

    def _validate_ca_certificate_from_serializer(self, credential_serializer: CredentialSerializer) -> x509.Certificate:
        """Validates that the certificate is a CA certificate."""
        cert_crypto = credential_serializer.certificate
        if cert_crypto is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        self._validate_ca_certificate(cert_crypto)
        self._check_duplicate_issuing_ca(cert_crypto)
        return cert_crypto

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

        pkcs12_raw, pkcs12_password = self._read_and_encode_pkcs12_file(cleaned_data)
        credential_serializer = self._parse_and_prepare_credential(pkcs12_raw, pkcs12_password, unique_name)
        cert_crypto = self._validate_ca_certificate_from_serializer(credential_serializer)

        self._finalize_issuing_ca_creation(unique_name, cert_crypto, credential_serializer)


class IssuingCaAddFileImportSeparateFilesForm(IssuingCaImportMixin, LoggerMixin, forms.Form):
    """Form for importing an Issuing CA using separate files.

    This form allows the user to upload a private key file, its password (optional),
    an Issuing CA certificate file, and an optional certificate chain. The form
    validates the uploaded files, ensuring they are correctly formatted, within
    size limits, and not already associated with an existing Issuing CA.

    Attributes:
        unique_name (CharField): A unique name for the Issuing CA.
        private_key_file (FileField): The private key file (.key, .pem).
        private_key_file_password (CharField): An optional password for the private key.
        ca_certificate (FileField): The Issuing CA certificate file (.cer, .der, .pem, .p7b, .p7c).
        ca_certificate_chain (FileField): An optional certificate chain file.
    """

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

        self._validate_ca_certificate(cert_crypto)
        self._check_duplicate_issuing_ca(cert_crypto)

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

    def _validate_credential_components(
        self, credential_serializer: CredentialSerializer
    ) -> tuple[x509.Certificate, Any]:
        """Validates the private key and certificate from the credential serializer.

        Args:
            credential_serializer: The credential serializer containing the private key and certificate.

        Returns:
            A tuple containing the certificate and private key.

        Raises:
            ValidationError: If the certificate or private key is missing or they don't match.
        """
        pk = credential_serializer.private_key
        cert = credential_serializer.certificate

        if cert is None:
            self._raise_validation_error('Certificate is missing from credential serializer.')
        if pk is None:
            self._raise_validation_error('Private key is missing from credential serializer.')

        # After the None checks above, mypy needs explicit assertion that these are not None
        assert cert is not None  # noqa: S101
        assert pk is not None  # noqa: S101

        if pk.public_key() != cert.public_key():
            self._raise_validation_error('The provided private key does not match the Issuing CA certificate.')

        return cert, pk

    def _prepare_credential_serializer(
        self, credential_serializer: CredentialSerializer, unique_name: str | None, pk: Any
    ) -> None:
        """Prepares the credential serializer with private key reference."""
        if credential_serializer.private_key is None:
            self._raise_validation_error('Private key is missing from credential serializer.')

        private_key_location = get_private_key_location_from_config()
        credential_serializer.private_key_reference = (
            PrivateKeyReference.from_private_key(
                private_key=pk,
                key_label=unique_name,
                location=private_key_location
            )
        )

    def clean(self) -> None:
        """Cleans and validates the form data.

        This method performs additional validation on the provided data,
        such as ensuring the unique name, private key file, and certificates
        are valid. It also initializes and saves the issuing CA configuration
        if all checks pass.

        Raises:
            ValidationError: If the form data is invalid or there is an error during processing.
        """
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

        cert, pk = self._validate_credential_components(credential_serializer)
        self._prepare_credential_serializer(credential_serializer, unique_name, pk)

        self._finalize_issuing_ca_creation(unique_name, cert, credential_serializer)


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


class CertProfileConfigForm(LoggerMixin, forms.ModelForm[CertificateProfileModel]):
    """Form for creating or updating Certificate Profiles.

    This form is based on the CertificateProfileModel and allows users to
    create or update certificate profiles by specifying a unique name and
    profile JSON configuration.

    Attributes:
        unique_name (CharField): A unique name for the certificate profile.
        profile_json (JSONField): The JSON configuration for the certificate profile.
    """

    class Meta:
        """Meta information for the CertProfileConfigForm."""

        model = CertificateProfileModel
        fields: ClassVar[list[str]] = ['unique_name', 'profile_json','is_default']

    def clean_unique_name(self) -> str:
        """Validates the unique name to ensure it is not already in use.

        Raises:
            ValidationError: If the unique name is already associated with an existing certificate profile.
        """
        unique_name = self.cleaned_data['unique_name']
        qs = CertificateProfileModel.objects.filter(unique_name=unique_name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            error_message = 'Unique name is already taken. Choose another one.'
            raise ValidationError(error_message)
        return cast('str', unique_name)

    def clean_profile_json(self) -> str:
        """Validates the profile JSON to ensure it is a valid certificate profile.

        Raises:
            ValidationError: If the profile JSON is not a valid certificate profile.
        """
        profile_json = self.cleaned_data['profile_json']
        if type(profile_json) is dict:
            json_dict = profile_json
        else:
            try:
                json_dict = json.loads(str(profile_json))
            except json.JSONDecodeError as e:
                error_message = f'Invalid JSON format: {e!s}'
                raise forms.ValidationError(error_message) from e
        try:
            CertProfilePydanticModel.model_validate(json_dict)
        except PydanticValidationError as e:
            error_message = f'This JSON is not a valid certificate profile: {e!s}'
            raise forms.ValidationError(error_message) from e
        self.instance.display_name = json_dict.get('display_name', '')
        return json.dumps(json_dict)


class IssuingCaAddRequestMixin(LoggerMixin, forms.ModelForm[CaModel]):
    """Mixin for forms requesting an Issuing CA certificate from remote servers."""

    class Meta:
        """Meta class for IssuingCaAddRequestMixin."""
        model = CaModel
        fields: ClassVar[list[str]] = [
            'unique_name', 'remote_host', 'remote_port', 'remote_path', 'est_username', 'ca_type'
        ]

    key_type = forms.ChoiceField(
        label=_('Key Type'),
        choices=[
            ('RSA-2048', 'RSA 2048'),
            ('RSA-3072', 'RSA 3072'),
            ('RSA-4096', 'RSA 4096'),
            ('ECC-SECP256R1', 'ECC SECP256R1'),
            ('ECC-SECP384R1', 'ECC SECP384R1'),
            ('ECC-SECP521R1', 'ECC SECP521R1'),
            ('ECC-SECP256K1', 'ECC SECP256K1'),
            ('ECC-BRAINPOOLP256R1', 'ECC BRAINPOOLP256R1'),
            ('ECC-BRAINPOOLP384R1', 'ECC BRAINPOOLP384R1'),
            ('ECC-BRAINPOOLP512R1', 'ECC BRAINPOOLP512R1'),
        ],
        initial='RSA-2048',
        required=True,
        help_text=_('Select the cryptographic key type and parameters'),
    )

    def clean(self) -> dict[str, Any]:
        """Validate the form data."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        remote_host = cleaned_data.get('remote_host')
        remote_port = cleaned_data.get('remote_port')
        remote_path = cleaned_data.get('remote_path')

        if remote_host and remote_path:
            try:
                validate_remote_ca_connection(remote_host, remote_port, remote_path)
            except UtilValidationError as e:
                msg = f'Remote CA connection validation failed: {e}'
                raise forms.ValidationError(msg) from e

        return cleaned_data

    def _create_credential(self) -> CredentialModel:
        """Create and return a temporary credential for the CA."""
        key_type = self.cleaned_data['key_type']
        if key_type.startswith('RSA-'):
            rsa_key_size = int(key_type.split('-')[1])
            public_key_info = PublicKeyInfo(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA,
                key_size=rsa_key_size
            )
        else:
            curve_name = key_type.split('-')[1]
            named_curve = NamedCurve[curve_name.upper()]
            public_key_info = PublicKeyInfo(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
                named_curve=named_curve
            )

        private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info)

        temp_cert, _ = CertificateGenerator.create_root_ca(
            cn=f'Temp-{uuid.uuid4()}',
            validity_days=1,
            private_key=private_key
        )

        cred_serializer = CredentialSerializer(
            certificate=temp_cert,
            private_key=private_key,
            additional_certificates=[]
        )

        return CredentialModel.save_credential_serializer(
            cred_serializer, CredentialModel.CredentialTypeChoice.ISSUING_CA
        )

    def save(self) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration."""
        instance = super().save(commit=False)

        instance.credential = self._create_credential()

        return instance


class IssuingCaAddRequestEstForm(IssuingCaAddRequestMixin):
    """Form for requesting an Issuing CA certificate using EST."""

    class Meta:
        """Meta class for IssuingCaAddRequestEstForm."""
        model = CaModel
        fields: ClassVar[list[str]] = [
            'unique_name', 'remote_host', 'remote_port', 'remote_path', 'est_username', 'est_password', 'ca_type'
        ]

    est_username = forms.CharField(
        label=_('EST Username'),
        max_length=128,
        required=True,
        help_text=_('Username for EST authentication'),
    )

    est_password = forms.CharField(
        label=_('EST Password'),
        widget=forms.PasswordInput,
        required=True,
        help_text=_('Password for EST authentication'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)
        self.fields['remote_port'].initial = 443
        self.fields['remote_path'].initial = '/.well-known/est/simpleenroll'
        self.fields['ca_type'].initial = CaModel.CaTypeChoice.REMOTE_ISSUING_EST
        self.fields['ca_type'].widget = forms.HiddenInput()

    def save(self) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration."""
        instance = super().save()

        no_onboarding_config = NoOnboardingConfigModel.objects.create(
            pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            est_password=self.cleaned_data['est_password'],
            trust_store=None,  # Will be set later via truststore association
        )
        instance.no_onboarding_config = no_onboarding_config
        instance.est_username = self.cleaned_data['est_username']

        instance.save()
        return instance


class IssuingCaAddRequestCmpForm(IssuingCaAddRequestMixin):
    """Form for requesting an Issuing CA certificate using CMP."""

    class Meta:
        """Meta class for IssuingCaAddRequestCmpForm."""
        model = CaModel
        fields: ClassVar[list[str]] = [
            'unique_name', 'remote_host', 'remote_port', 'remote_path', 'ca_type'
        ]

    cmp_shared_secret = forms.CharField(
        label=_('CMP Shared Secret'),
        widget=forms.PasswordInput,
        required=True,
        help_text=_('Shared secret for CMP authentication'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        super().__init__(*args, **kwargs)
        self.fields['remote_port'].initial = 443
        self.fields['remote_path'].initial = '/.well-known/cmp/p/certification'
        self.fields['ca_type'].initial = CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
        self.fields['ca_type'].widget = forms.HiddenInput()

    def save(self) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration."""
        instance = super().save()

        no_onboarding_config = NoOnboardingConfigModel.objects.create(
            pki_protocols=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
            cmp_shared_secret=self.cleaned_data['cmp_shared_secret'],
            trust_store=None,  # Will be set later via truststore association
        )
        instance.no_onboarding_config = no_onboarding_config

        instance.save()
        return instance


class ProfileBasedFormFieldBuilder:
    """Django form field builder that leverages JSONProfileVerifier.

    This builder uses JSONProfileVerifier.get_sample_request() to understand the
    profile structure, eliminating the need for manual profile parsing logic.

    Attributes:
        profile: The certificate profile definition
        verifier: JSONProfileVerifier instance for profile interpretation
        fields: Dictionary of generated Django form fields
    """

    SUBJECT_LABELS: ClassVar[dict[str, str]] = {
        'cn': 'Common Name (CN)',
        'common_name': 'Common Name (CN)',
        'o': 'Organization (O)',
        'organization_name': 'Organization (O)',
        'ou': 'Organizational Unit (OU)',
        'organizational_unit_name': 'Organizational Unit (OU)',
        'c': 'Country (C)',
        'country_name': 'Country (C)',
        'st': 'State or Province (ST)',
        'state_or_province_name': 'State or Province (ST)',
        'l': 'Locality (L)',
        'locality_name': 'Locality (L)',
        'emailAddress': 'Email Address',
        'email_address': 'Email Address',
    }

    SAN_LABELS: ClassVar[dict[str, str]] = {
        'dns_names': 'DNS Names (comma separated)',
        'ip_addresses': 'IP Addresses (comma separated)',
        'rfc822_names': 'Email Addresses (comma separated)',
        'uris': 'URIs (comma separated)',
    }

    VALIDITY_LABELS: ClassVar[dict[str, str]] = {
        'days': 'Days',
        'hours': 'Hours',
        'minutes': 'Minutes',
        'seconds': 'Seconds',
    }

    def __init__(self, profile: dict[str, Any]) -> None:
        """Initialize the builder with a profile.

        Args:
            profile: Certificate profile definition
        """
        self.profile = profile
        self.verifier = JSONProfileVerifier(profile)
        self.fields: dict[str, forms.Field] = {}

    def build_all_fields(self) -> dict[str, forms.Field]:
        """Build all fields from the profile by analyzing a sample request.

        This leverages JSONProfileVerifier.get_sample_request() to understand
        the profile structure, eliminating manual parsing.
        """
        sample_request = self.verifier.get_sample_request()

        self._build_fields_from_sample(sample_request)

        return self.fields

    def _build_fields_from_sample(self, sample_request: dict[str, Any]) -> None:
        """Build form fields based on the sample request structure."""
        subject = sample_request.get('subject', {})
        profile_subject = self.profile.get('subj', {})

        if profile_subject.get('allow') == '*':
            self._build_all_subject_fields(profile_subject)
        elif subject:
            self._build_subject_fields_from_sample(subject)

        extensions = sample_request.get('extensions', {})
        if extensions:
            san = extensions.get('subject_alternative_name', {})
            profile_extensions = self.profile.get('ext', {})
            profile_san = profile_extensions.get('subject_alternative_name', profile_extensions.get('san', {}))

            if isinstance(profile_san, dict) and profile_san.get('allow') == '*':
                self._build_all_san_fields(profile_san)
            elif san:
                self._build_san_fields_from_sample(san)

        validity = sample_request.get('validity', {})
        if validity:
            self._build_validity_fields_from_sample(validity)

    def _build_all_subject_fields(self, profile_subject: dict[str, Any]) -> None:
        """Build all possible subject fields when allow='*'."""
        for field_name in self.SUBJECT_LABELS:
            if field_name in ('cn', 'o', 'ou', 'c', 'st', 'l', 'emailAddress'):
                continue

            field_spec = profile_subject.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
            else:
                is_required = False
                is_mutable = True
                field_value = ''

            display_label = self.SUBJECT_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value else ''

            if field_name in ('c', 'country_name'):
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'}),
                    min_length=2,
                    max_length=2
                )
            else:
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'})
                )

    def _build_all_san_fields(self, profile_san: dict[str, Any]) -> None:
        """Build all possible SAN fields when allow='*'."""
        for field_name in self.SAN_LABELS:
            field_spec = profile_san.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
                if isinstance(field_value, list):
                    field_value = ', '.join(str(v) for v in field_value)
            else:
                is_required = False
                is_mutable = True
                field_value = ''

            display_label = self.SAN_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value else ''

            self.fields[field_name] = forms.CharField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.TextInput(attrs={'class': 'form-control'})
            )

    def _build_subject_fields_from_sample(self, subject: dict[str, Any]) -> None:
        """Build subject fields based on sample values."""
        profile_subject = self.profile.get('subj', {})

        for field_name, sample_value in subject.items():
            if field_name in CERT_PROFILE_KEYWORDS:
                continue

            field_spec = profile_subject.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
            else:
                is_required = field_name in profile_subject.get('required', [])
                is_mutable = (
                    field_name in profile_subject.get('mutable', [])
                    or field_name not in profile_subject.get('value', {})
                )
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                field_value = '' if is_changeme else sample_value

            display_label = self.SUBJECT_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value else ''

            if field_name in ('c', 'country_name'):
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'}),
                    min_length=2,
                    max_length=2
                )
            else:
                self.fields[field_name] = forms.CharField(
                    required=is_required,
                    label=mark_safe(display_label),  # noqa: S308
                    initial=initial_value,
                    disabled=not is_mutable,
                    widget=forms.TextInput(attrs={'class': 'form-control'})
                )

    def _build_san_fields_from_sample(self, san: dict[str, Any]) -> None:
        """Build SAN fields based on sample values."""
        profile_extensions = self.profile.get('ext', {})
        profile_san = profile_extensions.get('subject_alternative_name', profile_extensions.get('san', {}))

        for field_name, sample_value in san.items():
            if field_name in CERT_PROFILE_KEYWORDS or field_name == 'critical':
                continue

            field_spec = profile_san.get(field_name, {}) if isinstance(profile_san, dict) else {}
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', ''))
                if isinstance(field_value, list):
                    field_value = ', '.join(str(v) for v in field_value)
            else:
                is_required = field_name in profile_san.get('required', []) if isinstance(profile_san, dict) else False
                is_mutable = (
                    field_name in profile_san.get('mutable', [])
                    or field_name not in profile_san.get('value', {})
                ) if isinstance(profile_san, dict) else True
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                if is_changeme:
                    field_value = ''
                elif isinstance(sample_value, list):
                    field_value = ', '.join(str(v) for v in sample_value)
                else:
                    field_value = sample_value if sample_value else ''

            display_label = self.SAN_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value else ''

            self.fields[field_name] = forms.CharField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.TextInput(attrs={'class': 'form-control'})
            )

    def _build_validity_fields_from_sample(self, validity: dict[str, Any]) -> None:
        """Build validity fields based on sample values."""
        profile_validity = self.profile.get('validity', {})

        for field_name, sample_value in validity.items():
            if field_name in CERT_PROFILE_KEYWORDS or field_name in ('not_before', 'not_after', 'duration'):
                continue

            field_spec = profile_validity.get(field_name, {})
            if isinstance(field_spec, dict):
                is_required = field_spec.get('required', False)
                is_mutable = field_spec.get('mutable', True)
                field_value = field_spec.get('value', field_spec.get('default', 0))
            else:
                is_required = field_name in profile_validity.get('required', [])
                is_mutable = (
                    field_name in profile_validity.get('mutable', [])
                    or field_name not in profile_validity.get('value', {})
                )
                is_changeme = isinstance(sample_value, str) and sample_value.startswith('CHANGEME_')
                field_value = 0 if is_changeme else (sample_value if sample_value is not None else 0)

            display_label = self.VALIDITY_LABELS.get(field_name, field_name.replace('_', ' ').title())

            if is_required:
                display_label += ' <span class="badge" style="background-color: #dc3545; color: white;">Required</span>'

            initial_value = field_value if field_value is not None else 0

            self.fields[field_name] = forms.IntegerField(
                required=is_required,
                label=mark_safe(display_label),  # noqa: S308
                initial=initial_value,
                disabled=not is_mutable,
                widget=forms.NumberInput(attrs={'class': 'form-control'})
            )


class CertificateIssuanceForm(forms.Form):
    """Form for certificate issuance based on a certificate profile.

    This form dynamically generates fields based on a certificate profile and
    leverages existing infrastructure for profile interpretation and certificate building:

    - Uses JSONProfileVerifier.get_sample_request() to understand what fields to show
    - Validates user input with JSONProfileVerifier.apply_profile_to_request()
    - Delegates certificate building to JSONCertRequestConverter.from_json()

    This eliminates code duplication and ensures consistent profile interpretation
    across the application (55% code reduction from original implementation).

    Attributes:
        profile: The certificate profile definition
        verifier: JSONProfileVerifier instance for validation
        fields: Dynamically generated Django form fields
    """

    def __init__(self, profile: dict[str, Any], *args: Any, **kwargs: Any) -> None:
        """Initialize the form with a profile.

        Args:
            profile: Certificate profile definition (JSON format)
            *args: Additional positional arguments passed to parent form
            **kwargs: Additional keyword arguments passed to parent form
        """
        super().__init__(*args, **kwargs)
        self.profile = profile
        self.verifier = JSONProfileVerifier(profile)

        field_builder = ProfileBasedFormFieldBuilder(profile)
        self.fields = field_builder.build_all_fields()

    def get_certificate_builder(self) -> CertificateBuilder:
        """Build a CertificateBuilder from the form data.

        This method converts the form data to JSON format and delegates
        to JSONCertRequestConverter.from_json() to create the CertificateBuilder.

        Returns:
            CertificateBuilder ready for signing
        """
        cert_request = self._form_data_to_json_request()

        validated_request = self.verifier.apply_profile_to_request(cert_request)

        return JSONCertRequestConverter.from_json(validated_request)

    def _form_data_to_json_request(self) -> dict[str, Any]:
        """Convert cleaned form data to JSON certificate request format.

        Returns:
            dict: JSON certificate request compatible with JSONCertRequestConverter
        """
        cleaned_data = self.cleaned_data
        request: dict[str, Any] = {'type': 'cert_request'}

        subject = self._build_subject_from_form_data(cleaned_data)
        if subject:
            request['subject'] = subject

        extensions = self._build_extensions_from_form_data(cleaned_data)
        if extensions:
            request['extensions'] = extensions

        validity = self._build_validity_from_form_data(cleaned_data)
        if validity:
            request['validity'] = validity

        return request

    def _build_subject_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, str]:
        """Build subject DN from form data.

        This method handles both abbreviated and full field names.
        """
        return {
            field_name: value
            for field_name, value in cleaned_data.items()
            if field_name in ProfileBasedFormFieldBuilder.SUBJECT_LABELS and value
        }

    def _build_extensions_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, Any]:
        """Build certificate extensions from form data."""
        extensions = {}

        san = self._build_san_from_form_data(cleaned_data)
        if san:
            extensions['subject_alternative_name'] = san

        return extensions

    def _build_san_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, list[str]]:
        """Build SAN extension from form data."""
        san = {}
        for field_name in ProfileBasedFormFieldBuilder.SAN_LABELS:
            value = cleaned_data.get(field_name)
            if value:
                values = [v.strip() for v in value.split(',') if v.strip()]
                if values:
                    san[field_name] = values
        return san

    def _build_validity_from_form_data(self, cleaned_data: dict[str, Any]) -> dict[str, int]:
        """Build validity period from form data."""
        validity = {}
        for field_name in ProfileBasedFormFieldBuilder.VALIDITY_LABELS:
            value = cleaned_data.get(field_name)
            if value:
                validity[field_name] = int(value)
        return validity



class IssuingCaTruststoreAssociationForm(forms.Form):
    """Form for associating a truststore with an Issuing CA."""

    trust_store = forms.ModelChoiceField(
        queryset=TruststoreModel.objects.filter(intended_usage=TruststoreModel.IntendedUsage.TLS),
        empty_label='----------',
        required=True,
        label=_('Trust Store'),
        help_text=_('Select a trust store to associate with this Issuing CA'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        self.instance: CaModel = kwargs.pop('instance')
        super().__init__(*args, **kwargs)

        if self.instance.no_onboarding_config and self.instance.no_onboarding_config.trust_store:
            self.fields['trust_store'].initial = self.instance.no_onboarding_config.trust_store

    def save(self) -> None:
        """Save the truststore association to the CA's onboarding config."""
        if not self.instance.no_onboarding_config:
            err_msg = _('Expected CaModel that has a no_onboarding_config.')
            raise forms.ValidationError(err_msg)

        self.instance.no_onboarding_config.trust_store = self.cleaned_data['trust_store']
        self.instance.no_onboarding_config.full_clean()
        self.instance.no_onboarding_config.save()
