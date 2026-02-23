"""Django forms for issuing CA configuration and management."""

from __future__ import annotations

from typing import Any, ClassVar, NoReturn, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
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
from pki.models import CaModel
from pki.models.ca import MIN_CRL_CYCLE_INTERVAL_HOURS
from pki.models.certificate import CertificateModel
from pki.models.credential import CredentialModel
from pki.models.truststore import TruststoreModel
from pki.util.x509 import CertificateVerifier
from trustpoint.logger import LoggerMixin
from util.field import UniqueNameValidator, get_certificate_name
from util.validation import ValidationError as UtilValidationError
from util.validation import validate_remote_ca_connection


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

    def _verify_ca_cert_with_chain(
        self,
        cert: x509.Certificate,
        chain: list[x509.Certificate],
    ) -> None:
        """Verifies the CA certificate using the provided chain.

        The chain certificates are treated as untrusted intermediates used to
        build the path. The last certificate in the chain (or the cert itself if
        the chain is empty) is used as the trust anchor.

        If no chain is provided, the certificate is verified as self-signed.

        Args:
            cert: The CA certificate to verify.
            chain: Optional list of intermediate/root certificates for chain building.

        Raises:
            ValidationError: If certificate verification fails.
        """
        try:
            if chain:
                # Use the last cert in the chain as the trust anchor (root)
                trusted_roots = [chain[-1]]
                untrusted_intermediates = chain[:-1]
            else:
                # No chain provided — verify as self-signed
                trusted_roots = [cert]
                untrusted_intermediates = []

            CertificateVerifier.verify_ca_cert(
                cert=cert,
                trusted_roots=trusted_roots,
                untrusted_intermediates=untrusted_intermediates,
            )
        except ValueError as e:
            self._raise_validation_error(
                f'CA certificate verification failed: {e}'
            )

    def _finalize_issuing_ca_creation(
        self, unique_name: str | None, cert: x509.Certificate, credential_serializer: CredentialSerializer,
        chain: list[x509.Certificate] | None = None,
    ) -> None:
        """Finalizes the creation of the Issuing CA after validation."""
        if not unique_name:
            unique_name = get_certificate_name(cert)

        if CaModel.objects.filter(unique_name=unique_name).exists():
            self._raise_validation_error('Unique name is already taken. Choose another one.')

        self._verify_ca_cert_with_chain(cert, chain or [])

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

        chain = list(credential_serializer.additional_certificates or [])
        self._finalize_issuing_ca_creation(unique_name, cert_crypto, credential_serializer, chain)


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

        chain = list(credential_serializer.additional_certificates or [])
        self._finalize_issuing_ca_creation(unique_name, cert, credential_serializer, chain)

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


        cred_serializer = CredentialSerializer(
            private_key=private_key,
            additional_certificates=[]
        )

        return CredentialModel.save_credential_serializer(
            cred_serializer, CredentialModel.CredentialTypeChoice.ISSUING_CA
        )

    def save(self, *, commit: bool = True) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration."""
        instance = super().save(commit=False)

        instance.credential = self._create_credential()

        if commit:
            instance.save()
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

    def save(self, *, is_ra_mode: bool = False) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration.

        If is_ra_mode is True, create a REMOTE_EST_RA (Registration Authority) instead of REMOTE_ISSUING_EST.
        """
        if is_ra_mode:
            instance = super().save(commit=False)
            instance.ca_type = CaModel.CaTypeChoice.REMOTE_EST_RA
            instance.credential = None
            instance.certificate = None  # Will be set from truststore later
        else:
            instance = super().save(commit=False)
            instance.ca_type = CaModel.CaTypeChoice.REMOTE_ISSUING_EST
            instance.credential = self._create_credential()

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
    """Generic form for configuring a remote CMP endpoint (CA or RA).

    This form is used for both requesting an Issuing CA certificate via CMP and
    for setting up a remote CMP RA (Registration Authority) configuration.

    Fields include remote host, port, path, and the shared secret for CMP
    authentication. The form can be extended or reused for both CA and RA
    scenarios.
    """

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

    def save(self, *, is_ra_mode: bool = False) -> CaModel:  # type: ignore[override]
        """Save the form and create the CA model with configuration.

        If is_ra_mode is True, create a REMOTE_CMP_RA (Registration Authority) instead of REMOTE_ISSUING_CMP.
        """
        if is_ra_mode:
            instance = super(IssuingCaAddRequestMixin, self).save(commit=False)
            instance.ca_type = CaModel.CaTypeChoice.REMOTE_CMP_RA
            instance.credential = None
            instance.certificate = None  # Will be set from truststore later
        else:
            instance = super().save(commit=False)
            instance.ca_type = CaModel.CaTypeChoice.REMOTE_ISSUING_CMP
            instance.credential = self._create_credential()

        no_onboarding_config = NoOnboardingConfigModel.objects.create(
            pki_protocols=NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
            cmp_shared_secret=self.cleaned_data['cmp_shared_secret'],
            trust_store=None,  # Will be set later via truststore association
        )
        instance.no_onboarding_config = no_onboarding_config

        instance.save()
        return instance


class IssuingCaTruststoreAssociationForm(forms.Form):
    """Form for associating a truststore with an Issuing CA."""


    trust_store = forms.ModelChoiceField(
        queryset=TruststoreModel.objects.none(),  # Set in __init__
        empty_label='----------',
        required=True,
        label=_('Trust Store'),
        help_text=_('Select a trust store to associate with this Issuing CA'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the form."""
        self.instance: CaModel = kwargs.pop('instance')
        super().__init__(*args, **kwargs)

        # Cast to ModelChoiceField to access queryset attribute
        # Use forms.ModelChoiceField string literal for mypy type checking
        trust_store_field = cast('forms.ModelChoiceField[TruststoreModel]', self.fields['trust_store'])

        # For EST RA: check if this is the first or second truststore association
        if self.instance.ca_type == CaModel.CaTypeChoice.REMOTE_EST_RA:
            if not self.instance.certificate:
                trust_store_field.queryset = TruststoreModel.objects.filter(
                    intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
                )
                trust_store_field.help_text = _(
                    'EST RA (Step 1/2): Import the Issuing CA chain. This establishes the RA certificate and hierarchy.'
                )
            else:
                trust_store_field.queryset = TruststoreModel.objects.filter(
                    intended_usage=TruststoreModel.IntendedUsage.TLS
                )
                trust_store_field.help_text = _(
                    'EST RA (Step 2/2): Import the TLS server certificate (used for HTTPS connection security).'
                )
        elif self.instance.ca_type in [CaModel.CaTypeChoice.REMOTE_ISSUING_CMP, CaModel.CaTypeChoice.REMOTE_CMP_RA]:
            trust_store_field.queryset = TruststoreModel.objects.filter(
                intended_usage=TruststoreModel.IntendedUsage.ISSUING_CA_CHAIN
            )
            trust_store_field.help_text = _(
                'CMP: Only "Issuing CA Chain" truststores can be associated.'
            )
        else:
            trust_store_field.queryset = TruststoreModel.objects.filter(
                intended_usage=TruststoreModel.IntendedUsage.TLS
            )
            trust_store_field.help_text = _(
                'EST: Import the TLS server certificate of the remote PKI (used for HTTPS connection security)'
            )

        if self.instance.no_onboarding_config and self.instance.no_onboarding_config.trust_store:
            trust_store_field.initial = self.instance.no_onboarding_config.trust_store

    def save(self) -> None:
        """Save the truststore association to the CA's onboarding config."""
        if not self.instance.no_onboarding_config:
            err_msg = _('Expected CaModel that has a no_onboarding_config.')
            raise forms.ValidationError(err_msg)

        self.instance.no_onboarding_config.trust_store = self.cleaned_data['trust_store']
        self.instance.no_onboarding_config.full_clean()
        self.instance.no_onboarding_config.save()


class IssuingCaCrlCycleForm(forms.ModelForm[CaModel]):
    """Form for configuring CRL cycle settings for an Issuing CA."""

    class Meta:
        """Meta class for IssuingCaCrlCycleForm."""

        model = CaModel
        fields: ClassVar[list[str]] = [
            'crl_cycle_enabled',
            'crl_cycle_interval_hours',
            'crl_validity_hours',
        ]

    crl_cycle_enabled = forms.BooleanField(
        label=_('Enable CRL Cycle Updates'),
        required=False,
        help_text=_('Enable automatic periodic CRL generation for this CA'),
    )

    crl_cycle_interval_hours = forms.FloatField(
        label=_('CRL Cycle Interval (hours)'),
        initial=24,
        help_text=_('The interval in hours between CRL generations (minimum 5 minutes)'),
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': 'any'}),
    )

    crl_validity_hours = forms.FloatField(
        label=_('CRL Validity (hours)'),
        initial=24,
        help_text=_('The validity period in hours for generated CRLs'),
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': 'any'}),
    )

    def clean_crl_cycle_interval_hours(self) -> float:
        """Validate the CRL cycle interval."""
        interval = self.cleaned_data.get('crl_cycle_interval_hours')
        if interval is None:
            interval = 24
        interval_float = float(interval)
        if interval_float < MIN_CRL_CYCLE_INTERVAL_HOURS:
            raise ValidationError(_('CRL cycle interval must be at least 5 minutes'))
        return interval_float

    def save(self, *, commit: bool = True) -> CaModel:  # type: ignore[override]
        """Save the form and schedule the next CRL generation if enabled."""
        instance = super().save(commit=commit)
        if not isinstance(instance, CaModel):
            msg = 'Expected CaModel instance'
            raise TypeError(msg)

        if commit and instance.crl_cycle_enabled:
            instance.schedule_next_crl_generation()

        return instance
