# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django forms for owner credential management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NoReturn, cast

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

from pki.forms.credentials import (
    encode_credential_password,
    parse_certificate_chain_upload,
    parse_certificate_upload,
    parse_private_key_upload,
    read_pkcs12_upload,
)
from pki.key_types import KEY_TYPE_CHOICES
from pki.models import CaModel, RemoteIssuedCredentialModel
from pki.models.certificate import CertificateModel
from pki.models.domain import DomainModel
from pki.services.credential_upload import parse_pkcs12
from pki.services.key_generation import supported_key_type_choices
from trustpoint.logger import LoggerMixin
from util.field import UniqueNameValidator, get_certificate_name

if TYPE_CHECKING:
    from django.db.models.query import QuerySet


class OwnerCredentialFileImportForm(LoggerMixin, forms.Form):
    """Form for importing a DevOwnerID using separate files.

    The user uploads a private key file, its password (optional), a DevOwnerID
    certificate file, and an optional certificate chain. The certificate common
    name identifies the DevOwnerID in Trustpoint.

    Attributes:
        private_key_file (FileField): The private key file (.key, .pem).
        private_key_file_password (CharField): An optional password for the private key.
        certificate (FileField): The DevOwnerID certificate file (.cer, .der, .pem, .p7b, .p7c).
        certificate_chain (FileField): An optional certificate chain file.
    """

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
        """Validate and parse the uploaded private key with the shared helper."""
        return parse_private_key_upload(
            self.cleaned_data.get('private_key_file'),
            self.data.get('private_key_file_password') or None,
        )

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
        certificate_serializer = parse_certificate_upload(
            self.cleaned_data.get('certificate'),
            missing_message='No certificate file was uploaded.',
            too_large_message='Certificate file is too large, max. 64 kiB.',
            parse_message='Failed to parse the certificate. Seems to be corrupted.',
        )

        certificate_in_db = CertificateModel.get_cert_by_sha256_fingerprint(
            certificate_serializer.as_crypto().fingerprint(algorithm=hashes.SHA256()).hex()
        )
        if certificate_in_db:
            credential_in_db = (
                RemoteIssuedCredentialModel.objects.filter(
                    credential__certificate=certificate_in_db,
                    issued_credential_type=RemoteIssuedCredentialModel.RemoteIssuedCredentialType.DEV_OWNER_ID,
                )
                .select_related('credential__certificate')
                .first()
            )
            if credential_in_db is not None:
                err_msg = f'DevOwnerID {credential_in_db.common_name} is already configured with the same certificate.'
                raise ValidationError(err_msg)

        return certificate_serializer

    def clean_certificate_chain(self) -> CertificateCollectionSerializer | None:
        """Parse an optional certificate chain using shared upload limits."""
        return parse_certificate_chain_upload(
            self.cleaned_data.get('certificate_chain'),
            parse_message=_('Failed to parse the certificate chain. Seems to be corrupted.'),
        )

    def _raise_validation_error(self, message: str) -> NoReturn:
        """Helper method to raise a ValidationError with a given message.

        Args:
            message (str): The error message to be included in the ValidationError.

        Raises:
            ValidationError: Always raised with the provided message.
        """
        raise ValidationError(message)

    def clean(self) -> None:
        """Parse the uploaded files and store the DevOwnerID."""
        try:
            cleaned_data = super().clean()
            if not cleaned_data:
                return
            private_key_serializer = cleaned_data.get('private_key_file')
            certificate_serializer = cleaned_data.get('certificate')
            certificate_chain_serializer = cleaned_data.get('certificate_chain') or None

            if not private_key_serializer or not certificate_serializer:
                return

            common_name = get_certificate_name(certificate_serializer.as_crypto()) or ''
            if not common_name:
                self._raise_validation_error('Could not derive a common name from the certificate.')

            cleaned_data['common_name'] = common_name
            self.cleaned_data = cleaned_data

            credential_serializer = CredentialSerializer.from_serializers(
                private_key_serializer=private_key_serializer,
                certificate_serializer=certificate_serializer,
                certificate_collection_serializer=certificate_chain_serializer,
            )

            cleaned_data['_dev_owner_id_credential'] = RemoteIssuedCredentialModel.create_imported_dev_owner_id(
                common_name=common_name,
                credential_serializer=credential_serializer,
            )
            self.cleaned_data = cleaned_data
        except ValidationError:
            raise
        except Exception as exception:
            err_msg = str(exception)
            raise ValidationError(err_msg) from exception


class OwnerCredentialPkcs12ImportForm(forms.Form):
    """Import a DevOwnerID from a PKCS#12 file."""

    pkcs12_file = forms.FileField(label=_('PKCS#12 File (.p12, .pfx)'), required=True)
    pkcs12_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code'}),
        label=_('[Optional] PKCS#12 password'),
        required=False,
    )

    def clean(self) -> dict[str, Any]:
        """Parse the PKCS#12 container and store the DevOwnerID."""
        cleaned_data = cast('dict[str, Any]', super().clean())
        if not cleaned_data:
            return cleaned_data
        try:
            credential_serializer = parse_pkcs12(
                read_pkcs12_upload(cleaned_data.get('pkcs12_file')),
                encode_credential_password(cleaned_data.get('pkcs12_password'), pkcs12=True),
            )
            certificate = credential_serializer.certificate
            if certificate is None:
                raise ValidationError(_('The PKCS#12 file does not contain a certificate.'))  # noqa: TRY301
            common_name = get_certificate_name(certificate) or ''
            if not common_name:
                raise ValidationError(_('Could not derive a common name from the certificate.'))  # noqa: TRY301
            cleaned_data['common_name'] = common_name
            cleaned_data['_dev_owner_id_credential'] = RemoteIssuedCredentialModel.create_imported_dev_owner_id(
                common_name=common_name,
                credential_serializer=credential_serializer,
            )
        except ValidationError:
            raise
        except Exception as exception:
            raise ValidationError(str(exception)) from exception
        self.cleaned_data = cleaned_data
        return cleaned_data


class OwnerCredentialAddManagementCaForm(forms.Form):
    """Select a management CA that issues or forwards the DevOwnerID."""

    management_ca = forms.ModelChoiceField(
        queryset=CaModel.objects.none(),
        label=_('Management CA'),
        empty_label=None,
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Limit the CA choices to management CAs that can issue this certificate."""
        super().__init__(*args, **kwargs)
        from pki.services.management_issuance import available_management_cas  # noqa: PLC0415

        cast('forms.ModelChoiceField[Any]', self.fields['management_ca']).queryset = available_management_cas()


class OwnerCredentialExternalCsrKeyForm(forms.Form):
    """Key type for a DevOwnerID CSR signed by an external PKI."""

    key_type = forms.ChoiceField(label=_('Key Type'))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Offer only backend-supported key types."""
        super().__init__(*args, **kwargs)
        choices = supported_key_type_choices(KEY_TYPE_CHOICES)
        field = cast('forms.ChoiceField', self.fields['key_type'])
        field.choices = choices or [('', _('No supported backend algorithms available'))]


class OwnerCredentialExternalCsrCertificateForm(forms.Form):
    """Upload the certificate issued for a pending DevOwnerID CSR."""

    certificate = forms.FileField(label=_('Issued DevOwnerID Certificate (.pem, .der, .cer)'))
    certificate_chain = forms.FileField(label=_('[Optional] Certificate Chain'), required=False)

    def __init__(self, *args: Any, credential: Any, csr: Any, **kwargs: Any) -> None:
        """Bind validation to the pending key and CSR."""
        super().__init__(*args, **kwargs)
        self.credential = credential
        self.csr = csr
        self.chain: list[Any] = []

    def clean_certificate(self) -> CertificateSerializer:
        """Parse the certificate and verify it matches the pending CSR key and identity."""
        from pki.services.external_csr import certificate_matches_credential  # noqa: PLC0415

        serializer = parse_certificate_upload(
            self.cleaned_data.get('certificate'),
            missing_message=_('No certificate file was uploaded.'),
            too_large_message=_('Certificate file is too large, max. 64 kiB.'),
            parse_message=_('Failed to parse the DevOwnerID certificate.'),
        )
        certificate = serializer.as_crypto()
        if not certificate_matches_credential(certificate, self.credential):
            raise ValidationError(_('The uploaded certificate does not match the generated CSR key.'))
        if certificate.subject != self.csr.subject:
            raise ValidationError(_('The certificate subject does not match the generated CSR.'))
        return serializer

    def clean_certificate_chain(self) -> CertificateCollectionSerializer | None:
        """Parse an optional certificate chain."""
        chain = parse_certificate_chain_upload(
            self.cleaned_data.get('certificate_chain'),
            parse_message=_('Failed to parse the certificate chain.'),
        )
        self.chain = list(chain.as_crypto()) if chain else []
        return chain


class OwnerCredentialOnboardingSetupForm(forms.Form):
    """Combined form for setting up AOKI zero-touch onboarding after DevOwnerID file import.

    This form handles three things in a single step:
    1. Import a truststore (IDevID trust anchor) file
    2. Associate it with a domain
    3. Create a DevIdRegistration with a serial number regex pattern

    The serial number patterns are pre-populated from the IDevID references
    found in the uploaded DevOwnerID certificate's SAN.
    """

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope'}),
        required=False,
        validators=[UniqueNameValidator()],
    )

    trust_store_file = forms.FileField(
        label=_('IDevID Truststore File (.pem, .der, .p7b, .p7c)'),
        required=True,
        help_text=_(
            'Upload the trust anchor certificate(s) of the IDevID issuer. '
            'This is used to verify devices during AOKI zero-touch onboarding.'
        ),
    )

    domain_queryset: QuerySet[DomainModel] = DomainModel.objects.filter(is_active=True)
    domain = forms.ModelChoiceField(
        queryset=domain_queryset,
        label=_('Domain'),
        required=True,
        help_text=_('Select the domain to associate with this onboarding registration.'),
    )

    serial_number_pattern = forms.CharField(
        max_length=255,
        label=_('Serial Number Pattern (Regex)'),
        required=True,
        help_text=_(
            'A regex pattern to match valid IDevID serial numbers for this registration. '
            'Pre-populated from the DevOwnerID certificate references.'
        ),
        widget=forms.TextInput(
            attrs={
                'placeholder': 'e.g. ^[A-Z0-9-]+$ or specific pattern',
            }
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise the form, accepting the owner_credential instance."""
        self.owner_credential: RemoteIssuedCredentialModel = kwargs.pop('owner_credential')
        super().__init__(*args, **kwargs)

    def clean(self) -> dict[str, Any] | None:
        """Validate and create the truststore + DevIdRegistration."""
        from pki.models.devid_registration import DevIdRegistration  # noqa: PLC0415
        from pki.models.truststore import TruststoreModel  # noqa: PLC0415

        cleaned_data = cast('dict[str, Any]', super().clean())

        unique_name = cleaned_data.get('unique_name')
        trust_store_file = cleaned_data.get('trust_store_file')
        domain = cleaned_data.get('domain')
        serial_number_pattern = cleaned_data.get('serial_number_pattern')

        if not trust_store_file or not domain or not serial_number_pattern:
            return cleaned_data

        # Read and parse truststore file
        try:
            file_bytes = trust_store_file.read()
        except (OSError, AttributeError) as original_exception:
            raise ValidationError(_('Unexpected error reading the truststore file.')) from original_exception

        try:
            certificate_collection_serializer = CertificateCollectionSerializer.from_bytes(file_bytes)
        except Exception:  # noqa: BLE001
            try:
                certificate_serializer = CertificateSerializer.from_bytes(file_bytes)
                certificate_collection_serializer = CertificateCollectionSerializer(
                    [certificate_serializer.as_crypto()]
                )
            except Exception as exception:
                raise ValidationError(
                    _('Unable to process the truststore file. It may be malformed or corrupted.')
                ) from exception

        certs = certificate_collection_serializer.as_crypto()

        # Derive truststore name
        if not unique_name:
            unique_name = get_certificate_name(certs[0]) or self.owner_credential.common_name

        ts_name = f'idevid-ts-{unique_name}'
        counter = 1
        while TruststoreModel.objects.filter(unique_name=ts_name).exists():
            ts_name = f'idevid-ts-{unique_name}-{counter}'
            counter += 1

        # Create the truststore with IDevID intended usage
        try:
            from pki.forms.truststores import TruststoreAddForm  # noqa: PLC0415

            trust_store_model = TruststoreAddForm.save_trust_store(
                unique_name=ts_name,
                intended_usage=TruststoreModel.IntendedUsage.IDEVID,
                certificates=certs,
            )
        except Exception as e:
            raise ValidationError(_('Failed to save the truststore.')) from e

        # Create a DevIdRegistration name
        reg_name = f'reg-{unique_name}'
        counter = 1
        while DevIdRegistration.objects.filter(unique_name=reg_name).exists():
            reg_name = f'reg-{unique_name}-{counter}'
            counter += 1

        try:
            dev_id_registration = DevIdRegistration(
                unique_name=reg_name,
                truststore=trust_store_model,
                domain=domain,
                serial_number_pattern=serial_number_pattern,
            )
            dev_id_registration.save()
        except Exception as e:
            trust_store_model.delete()
            raise ValidationError(_('Failed to create the DevID registration pattern.')) from e

        cleaned_data['_truststore'] = trust_store_model
        cleaned_data['_dev_id_registration'] = dev_id_registration
        return cleaned_data
