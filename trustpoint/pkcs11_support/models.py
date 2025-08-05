from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class PKCS11Token(models.Model):
    """
    Model representing a PKCS#11 token (e.g., a SoftHSM slot/token pair).

    Stores metadata required to authenticate and interact with the token,
    including slot number, user and security officer PINs, and the path to
    the PKCS#11 module library.
    """

    label: str = models.CharField(
        max_length=100,
        unique=True,
        help_text=_("Token label in SoftHSM"),
        verbose_name=_("Label")
    )
    slot: int = models.PositiveIntegerField(
        help_text=_("Slot number in SoftHSM"),
        verbose_name=_("Slot")
    )
    user_pin: str = models.CharField(
        max_length=64,
        help_text=_("User PIN for token access"),
        verbose_name=_("User PIN")
    )
    so_pin: str = models.CharField(
        max_length=64,
        help_text=_("Security Officer PIN (admin)"),
        verbose_name=_("SO PIN")
    )
    module_path: str = models.CharField(
        max_length=255,
        default="/usr/lib/softhsm/libsofthsm2.so",
        help_text=_("Path to PKCS#11 module library"),
        verbose_name=_("Module Path")
    )
    created_at = models.DateTimeField(
        verbose_name=_('Created'),
        auto_now_add=True
    )

    class Meta:
        """
        Meta configuration for the PKCS11Token model.
        """
        verbose_name = _("PKCS#11 Token")
        verbose_name_plural = _("PKCS#11 Tokens")

    def __str__(self) -> str:
        """
        Returns a human-readable representation of the token.

        Returns:
            str: A string in the format "<label> (Slot <slot>)".
        """
        return f"{self.label} (Slot {self.slot})"
