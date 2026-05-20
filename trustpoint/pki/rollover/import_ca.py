"""Import CA rollover strategy — provisions the new CA by file upload."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from django import forms
from django.utils.translation import gettext_lazy as _
from trustpoint_core.serializer import (
    CredentialSerializer,
    PrivateKeyReference,
)

from pki.forms.issuing_cas import (
    IssuingCaImportMixin,
    get_ca_type_from_config,
    get_private_key_location_from_config,
)
from pki.models import CaModel
from pki.models.ca_rollover import CaRolloverStrategyType
from pki.rollover.base import RolloverStrategy
from pki.rollover.registry import rollover_registry
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models.ca_rollover import CaRolloverModel

logger = logging.getLogger(__name__)


class ImportCaRolloverForm(IssuingCaImportMixin, LoggerMixin, forms.Form):
    """Form for importing a new Issuing CA from a PKCS#12 file during rollover.

    Reuses the existing PKCS#12 import validation logic from IssuingCaImportMixin.
    """

    unique_name = forms.CharField(
        max_length=256,
        label=_('[Optional] Unique Name for new CA'),
        widget=forms.TextInput(attrs={'autocomplete': 'nope', 'class': 'form-control'}),
        required=False,
    )

    pkcs12_file = forms.FileField(
        label=_('PKCS#12 File (.p12, .pfx)'),
        required=True,
        widget=forms.ClearableFileInput(attrs={'class': 'form-control'}),
    )

    pkcs12_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'autocomplete': 'one-time-code', 'class': 'form-control'}),
        label=_('[Optional] PKCS#12 password'),
        required=False,
    )

    overlap_end = forms.DateTimeField(
        required=False,
        label=_('Overlap End Date'),
        help_text=_('Optional. When the old CA should stop being served in certificate chains.'),
        widget=forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
    )

    notes = forms.CharField(
        required=False,
        label=_('Notes'),
        help_text=_('Optional notes for audit purposes.'),
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
    )

    def clean(self) -> dict[str, Any] | None:
        """Validate the PKCS#12 file and create the new Issuing CA.

        The new CaModel is stored on the form instance as `new_issuing_ca`
        for retrieval by the strategy after validation.
        """
        cleaned_data = super().clean()
        if not cleaned_data:
            return cleaned_data

        unique_name = cleaned_data.get('unique_name')
        pkcs12_file = cleaned_data.get('pkcs12_file')
        pkcs12_password = cleaned_data.get('pkcs12_password')

        if pkcs12_file is None:
            msg = _('PKCS#12 file is required.')
            raise forms.ValidationError(msg)

        try:
            pkcs12_raw = pkcs12_file.read()
        except (OSError, AttributeError) as exc:
            msg = _('Failed to read the uploaded file.')
            raise forms.ValidationError(msg) from exc

        password_bytes: bytes | None = None
        if pkcs12_password:
            password_bytes = pkcs12_password.encode('utf-8')

        try:
            credential_serializer = CredentialSerializer.from_pkcs12_bytes(pkcs12_raw, password_bytes)
        except Exception as exc:
            msg = _('Failed to parse the PKCS#12 file. Wrong password or corrupted file.')
            raise forms.ValidationError(msg) from exc

        cert_crypto = credential_serializer.certificate
        if cert_crypto is None:
            self._raise_validation_error('Certificate is missing from the PKCS#12 file.')

        pk = credential_serializer.private_key
        if pk is None:
            self._raise_validation_error('Private key is missing from the PKCS#12 file.')

        if pk.public_key() != cert_crypto.public_key():
            self._raise_validation_error('The private key does not match the certificate.')

        self._validate_ca_certificate(cert_crypto)
        self._check_duplicate_issuing_ca(cert_crypto)

        private_key_location = get_private_key_location_from_config()
        credential_serializer.private_key_reference = PrivateKeyReference.from_private_key(
            private_key=pk,
            key_label=unique_name,
            location=private_key_location,
        )

        chain = list(credential_serializer.additional_certificates or [])
        self._verify_ca_cert_with_chain(cert_crypto, chain)

        new_ca = CaModel.create_new_issuing_ca(
            credential_serializer=credential_serializer,
            ca_type=get_ca_type_from_config(),
            unique_name=unique_name or None,
        )

        self._new_issuing_ca = new_ca
        return cleaned_data

    @property
    def new_issuing_ca(self) -> CaModel:
        """Return the newly created CaModel after successful validation.

        :raises AttributeError: If the form has not been validated yet.
        """
        return self._new_issuing_ca


class ImportCaRolloverStrategy(RolloverStrategy):
    """Rollover strategy: import a new Issuing CA from a PKCS#12 file.

    The new CA is available immediately at plan time — no AWAITING_NEW_CA state needed.
    """

    @property
    def strategy_type(self) -> CaRolloverStrategyType:
        """Return the strategy type identifier."""
        return CaRolloverStrategyType.IMPORT_CA

    @property
    def display_name(self) -> str:
        """Return a human-readable strategy name."""
        return str(_('Import new Issuing CA from file'))

    def get_plan_form(
        self,
        old_ca: CaModel,  # noqa: ARG002
        data: dict[str, object] | None = None,
        files: dict[str, object] | None = None,
    ) -> ImportCaRolloverForm:
        """Return the PKCS#12 import form.

        :param old_ca: The current Issuing CA (unused for import strategy).
        :param data: Optional POST data.
        :param files: Optional uploaded files.
        :returns: An ImportCaRolloverForm instance.
        """
        return ImportCaRolloverForm(data=data, files=files)

    def create_new_ca(self, form: forms.Form, old_ca: CaModel) -> CaModel | None:
        """Return the new CA created during form validation.

        :param form: The validated ImportCaRolloverForm.
        :param old_ca: The old Issuing CA being replaced.
        :returns: The new CaModel.
        """
        _ = old_ca
        if not isinstance(form, ImportCaRolloverForm):
            msg = 'Expected ImportCaRolloverForm instance.'
            raise TypeError(msg)
        return form.new_issuing_ca

    def on_complete(self, rollover: CaRolloverModel) -> None:
        """Reassign domains and deactivate the old CA when rollover completes.

        :param rollover: The completed rollover.
        """
        old_ca = rollover.old_issuing_ca
        new_ca = rollover.new_issuing_ca

        if new_ca is not None:
            updated = old_ca.domains.update(issuing_ca=new_ca)
            logger.info(
                'Reassigned %d domain(s) from old CA %s to new CA %s.',
                updated,
                old_ca.unique_name,
                new_ca.unique_name,
            )

        old_ca.is_active = False
        old_ca.save(update_fields=['is_active'])
        logger.info('Deactivated old CA %s after rollover completion.', old_ca.unique_name)

    def get_template_name(self) -> str:
        """Return the template for import-specific form fields."""
        return 'pki/issuing_cas/includes/rollover_import_ca_fields.html'


rollover_registry.register(ImportCaRolloverStrategy())
