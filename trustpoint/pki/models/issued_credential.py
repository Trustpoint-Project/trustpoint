"""A model for issued credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_stubs_ext.db.models import TypedModelMeta

from util.db import CustomDeleteActionModel

if TYPE_CHECKING:
    from pki.models.credential import CredentialModel  # noqa: F401


class RemoteIssuedCredentialModel(CustomDeleteActionModel):
    """Model for credentials issued to a CA, a DevOwnerID, or a device via a remote/RA CA."""

    class RemoteIssuedCredentialType(models.IntegerChoices):
        """The type of the credential."""

        DOMAIN_CREDENTIAL = 0, _('Domain Credential')
        DEV_OWNER_ID = 2, _('DevOwnerID')
        RA_DEVICE = 4, _('RA Device')

    id = models.AutoField(primary_key=True)

    common_name = models.CharField(verbose_name=_('Common Name'), max_length=255)
    issued_credential_type = models.IntegerField(
        choices=RemoteIssuedCredentialType, verbose_name=_('Credential Type'),
    )
    issued_using_cert_profile = models.CharField(
        max_length=255, verbose_name=_('Issued using Certificate Profile'), default='',
    )
    credential = models.OneToOneField(
        'pki.CredentialModel',
        verbose_name=_('Credential'),
        on_delete=models.CASCADE,
        related_name='remote_issued_credential',
        null=False,
        blank=False,
    )
    ca = models.ForeignKey(
        'pki.CaModel',
        verbose_name=_('CA'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    owner_credential = models.ForeignKey(
        'pki.OwnerCredentialModel',
        verbose_name=_('Owner Credential'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    device = models.ForeignKey(
        'devices.DeviceModel',
        verbose_name=_('Device'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )
    domain = models.ForeignKey(
        'pki.DomainModel',
        verbose_name=_('Domain'),
        on_delete=models.PROTECT,
        related_name='remote_issued_credentials',
        null=True,
        blank=True,
    )

    created_at = models.DateTimeField(verbose_name=_('Created'), auto_now_add=True)

    class Meta(TypedModelMeta):
        """Meta class configuration."""

    def __str__(self) -> str:
        """Returns a human-readable string representation."""
        return f'RemoteIssuedCredentialModel(common_name={self.common_name})'

    def clean(self) -> None:
        """Validate that exactly one owner (ca, owner_credential, or device) is set."""
        owners = [self.ca_id, self.owner_credential_id, self.device_id]
        set_count = sum(1 for o in owners if o is not None)
        if set_count == 0:
            raise ValidationError(_('One of ca, owner_credential, or device must be set.'))
        if set_count > 1:
            raise ValidationError(_('Only one of ca, owner_credential, or device may be set.'))

    def pre_delete(self) -> None:
        """Delete the underlying credential (cascades back to this model)."""
        self.credential.delete()
