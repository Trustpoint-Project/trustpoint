"""Django forms for owner credential management."""

from __future__ import annotations

from typing import Any, NoReturn

from cryptography.hazmat.primitives import hashes
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import KeyPairGenerator, NamedCurve, PublicKeyAlgorithmOid, PublicKeyInfo
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    CredentialSerializer,
    PrivateKeySerializer,
)

from onboarding.models import (
    NoOnboardingConfigModel,
    NoOnboardingPkiProtocol,
    OnboardingConfigModel,
    OnboardingPkiProtocol,
    OnboardingProtocol,
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
            from devices.models import IssuedCredentialModel  # noqa: PLC0415
            credential_qs = OwnerCredentialModel.objects.filter(
                issued_credentials__credential__certificate=certificate_in_db,
                issued_credentials__issued_credential_type=IssuedCredentialModel.IssuedCredentialType.DEV_OWNER_ID,
            )
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


class OwnerCredentialTruststoreAssociationForm(forms.Form):
    """Form for associating a TLS truststore with a DevOwnerID's NoOnboardingConfig.

    Only TLS-intended truststores are shown, because the truststore is used to
    verify the remote EST server's HTTPS certificate.
    """

    trust_store = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        empty_label='----------',
        required=True,
        label=_('TLS Trust Store'),
        help_text=_('Select a TLS trust store to verify the remote EST server certificate'),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise the form with the OwnerCredentialModel instance."""
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        self.instance: OwnerCredentialModel = kwargs.pop('instance')
        super().__init__(*args, **kwargs)

        trust_store_field = self.fields['trust_store']
        trust_store_field.queryset = TruststoreModel.objects.filter(  # type: ignore[union-attr]
            intended_usage=TruststoreModel.IntendedUsage.TLS
        )

        # Pre-select the already-associated truststore if one exists
        if self.instance.no_onboarding_config and self.instance.no_onboarding_config.trust_store:
            trust_store_field.initial = self.instance.no_onboarding_config.trust_store  # type: ignore[union-attr]

    def save(self) -> None:
        """Save the selected truststore to the owner credential's no-onboarding config."""
        if not self.instance.no_onboarding_config:
            raise forms.ValidationError(_('Expected OwnerCredentialModel with a no_onboarding_config.'))

        self.instance.no_onboarding_config.trust_store = self.cleaned_data['trust_store']
        self.instance.no_onboarding_config.full_clean()
        self.instance.no_onboarding_config.save()


_KEY_TYPE_CHOICES = [
    ('RSA-2048', 'RSA 2048'),
    ('RSA-3072', 'RSA 3072'),
    ('RSA-4096', 'RSA 4096'),
    ('ECC-SECP256R1', 'ECC SECP256R1'),
    ('ECC-SECP384R1', 'ECC SECP384R1'),
    ('ECC-SECP521R1', 'ECC SECP521R1'),
]


class _OwnerCredentialEstBaseMixin(LoggerMixin, forms.Form):
    """Shared fields and key-generation logic for EST-based DevOwnerID enrollment forms."""

    unique_name = forms.CharField(
        max_length=100,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    remote_host = forms.CharField(
        max_length=253,
        label=_('EST Server Host'),
        help_text=_('Hostname or IP address of the remote EST server'),
    )

    remote_port = forms.IntegerField(
        label=_('EST Server Port'),
        initial=443,
        min_value=1,
        max_value=65535,
    )

    remote_path = forms.CharField(
        max_length=255,
        label=_('EST Server Path'),
        initial='/.well-known/est/simpleenroll',
        help_text=_('Path component of the EST enrollment endpoint'),
    )

    key_type = forms.ChoiceField(
        label=_('Key Type'),
        choices=_KEY_TYPE_CHOICES,
        initial='RSA-2048',
        help_text=_('Cryptographic key type and size for the generated keypair'),
    )

    def _generate_private_key(self, key_type: str) -> Any:
        """Generate a private key according to the selected key_type choice string."""
        if key_type.startswith('RSA-'):
            key_size = int(key_type.split('-')[1])
            public_key_info = PublicKeyInfo(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA,
                key_size=key_size,
            )
        else:
            curve_name = key_type.split('-', 1)[1]
            named_curve = NamedCurve[curve_name.upper()]
            public_key_info = PublicKeyInfo(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
                named_curve=named_curve,
            )
        return KeyPairGenerator.generate_key_pair_for_public_key_info(public_key_info)

    def _resolve_unique_name(self, unique_name: str | None, host: str) -> str:
        """Return the given unique_name, or derive one from the remote host."""
        if unique_name:
            return unique_name
        # Fall back to host-based name; ensure uniqueness
        base = host
        candidate = base
        counter = 1
        while OwnerCredentialModel.objects.filter(unique_name=candidate).exists():
            candidate = f'{base}-{counter}'
            counter += 1
        return candidate


class OwnerCredentialAddRequestEstNoOnboardingForm(_OwnerCredentialEstBaseMixin):
    """Form for requesting a DevOwnerID certificate via EST with username/password (no IDevID onboarding).

    Generates a keypair locally, then enrolls with the remote EST server using
    HTTP Basic authentication.  On success the credential is stored and linked
    to the OwnerCredentialModel together with a NoOnboardingConfigModel.
    """

    est_username = forms.CharField(
        max_length=128,
        label=_('EST Username'),
        help_text=_('Username for EST Basic authentication'),
    )

    est_password = forms.CharField(
        label=_('EST Password'),
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        help_text=_('Password for EST Basic authentication'),
    )

    def clean(self) -> dict[str, Any]:
        """Validate and save the owner credential via EST no-onboarding enrollment."""
        cleaned_data: dict[str, Any] = super().clean() or {}

        unique_name = cleaned_data.get('unique_name')
        remote_host = cleaned_data.get('remote_host')
        est_username = cleaned_data.get('est_username')
        est_password = cleaned_data.get('est_password')
        key_type = cleaned_data.get('key_type', 'RSA-2048')
        remote_port = cleaned_data.get('remote_port', 443)
        remote_path = cleaned_data.get('remote_path', '/.well-known/est/simpleenroll')

        if not remote_host or not est_username or not est_password:
            return cleaned_data

        unique_name = self._resolve_unique_name(unique_name, remote_host)
        if OwnerCredentialModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError(_('An owner credential with this name already exists.'))

        cleaned_data['unique_name'] = unique_name

        private_key = self._generate_private_key(key_type)

        no_onboarding_config = NoOnboardingConfigModel(
            pki_protocols=NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
            est_password=est_password,
        )
        no_onboarding_config.save()

        cleaned_data['_private_key'] = private_key
        cleaned_data['_no_onboarding_config'] = no_onboarding_config
        cleaned_data['_remote_host'] = remote_host
        cleaned_data['_remote_port'] = remote_port
        cleaned_data['_remote_path'] = remote_path
        cleaned_data['_est_username'] = est_username

        return cleaned_data


class OwnerCredentialAddRequestEstOnboardingForm(_OwnerCredentialEstBaseMixin):
    """Form for requesting a DevOwnerID certificate via EST with IDevID-based onboarding.

    The device authenticates to the remote EST server using its manufacturer-issued
    IDevID certificate (mTLS client certificate).  A trust store for verifying the
    EST server's TLS certificate must be associated after this step.
    """

    idevid_trust_store = forms.ModelChoiceField(
        queryset=None,  # set in __init__
        required=False,
        empty_label=_('(none - skip server verification)'),
        label=_('IDevID Manufacturer Truststore'),
        help_text=_(
            'Optional: truststore containing the manufacturer CA to verify the EST server during IDevID enrollment'
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise queryset for the trust store choice field."""
        super().__init__(*args, **kwargs)
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415
        self.fields['idevid_trust_store'].queryset = TruststoreModel.objects.filter(  # type: ignore[union-attr]
            intended_usage=TruststoreModel.IntendedUsage.IDEVID
        )

    def clean(self) -> dict[str, Any]:
        """Validate and prepare the owner credential via EST IDevID onboarding."""
        cleaned_data: dict[str, Any] = super().clean() or {}

        unique_name = cleaned_data.get('unique_name')
        remote_host = cleaned_data.get('remote_host')
        key_type = cleaned_data.get('key_type', 'RSA-2048')
        remote_port = cleaned_data.get('remote_port', 443)
        remote_path = cleaned_data.get('remote_path', '/.well-known/est/simpleenroll')
        idevid_trust_store = cleaned_data.get('idevid_trust_store')

        if not remote_host:
            return cleaned_data

        unique_name = self._resolve_unique_name(unique_name, remote_host)
        if OwnerCredentialModel.objects.filter(unique_name=unique_name).exists():
            raise ValidationError(_('An owner credential with this name already exists.'))

        cleaned_data['unique_name'] = unique_name

        private_key = self._generate_private_key(key_type)

        onboarding_config = OnboardingConfigModel(
            pki_protocols=OnboardingPkiProtocol.EST,
            onboarding_protocol=OnboardingProtocol.EST_IDEVID,
            idevid_trust_store=idevid_trust_store,
        )
        onboarding_config.save()

        cleaned_data['_private_key'] = private_key
        cleaned_data['_onboarding_config'] = onboarding_config
        cleaned_data['_remote_host'] = remote_host
        cleaned_data['_remote_port'] = remote_port
        cleaned_data['_remote_path'] = remote_path

        return cleaned_data
