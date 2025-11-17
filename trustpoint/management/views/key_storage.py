"""Views for configuring PKCS#11 settings, including HSM PIN and token configuration."""

from typing import Any, ClassVar

from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from django.views.generic import TemplateView

from management.models import KeyStorageConfig, PKCS11Token


class KeyStorageConfigView(TemplateView):
    """Class-based view for displaying key storage configuration (read-only)."""
    template_name = 'management/key_storage.html'
    extra_context: ClassVar[dict[str, str]] = {'page_category': 'management', 'page_name': 'key_storage'}

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Add additional context to the template."""
        context = super().get_context_data(**kwargs)
        context['page_title'] = _('Key Storage Configuration')

        try:
            config = KeyStorageConfig.get_config()
            context['config'] = config

            if config.storage_type in [
                KeyStorageConfig.StorageType.SOFTHSM,
                KeyStorageConfig.StorageType.PHYSICAL_HSM
            ]:
                if config.hsm_config:
                    context['hsm_config'] = config.hsm_config
                else:
                    try:
                        context['hsm_config'] = PKCS11Token.objects.first()
                    except PKCS11Token.DoesNotExist:
                        context['hsm_config'] = None
        except KeyStorageConfig.DoesNotExist:
            context['config'] = None
            messages.warning(self.request, _('Key storage configuration not found.'))

        return context
