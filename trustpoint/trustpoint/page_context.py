"""This module contains page category objects providing the corresponding subcategories."""

from typing import Any, cast

DEVICES_PAGE_CATEGORY = 'devices'
DEVICES_PAGE_DEVICES_SUBCATEGORY = 'devices'
DEVICES_PAGE_OPC_UA_SUBCATEGORY = 'opc_ua_gds'
DEVICES_PAGE_OPC_UA_GDS_PUSH_SUBCATEGORY = 'opc_ua_gds_push'

PKI_PAGE_CATEGORY = 'pki'
PKI_PAGE_CERTIFICATES_SUBCATEGORY = 'certificates'
PKI_PAGE_DOMAIN_SUBCATEGORY = 'domains'
PKI_PAGE_ISSUING_CAS_SUBCATEGORY = 'issuing_cas'
PKI_PAGE_TRUSTSTORES_SUBCATEGORY = 'truststores'


class PageContextMixin:
    """Mixin which adds data to the context for the devices application."""

    page_category: str | None = None
    page_name: str | None = None

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        """Adds the page category and page_name for the device pages.

        Args:
            kwargs:
                The keyword arguments are passed to super().get_context_data() if it exists.
                Otherwise, kwargs is returned with the added page_category.

        Returns:
            The context data including the page_category information.
        """
        super_get_context = getattr(super(), 'get_context_data', None)
        context = cast('dict[str, Any]', super_get_context(**kwargs)) if callable(super_get_context) else kwargs

        if self.page_category is not None:
            context['page_category'] = self.page_category

        if self.page_name is not None:
            context['page_name'] = self.page_name

        # make these constants avaialable on all views, so that they can be used in the templates.
        context['DEVICES_PAGE_CATEGORY'] = DEVICES_PAGE_CATEGORY
        context['DEVICES_PAGE_DEVICES_SUBCATEGORY'] = DEVICES_PAGE_DEVICES_SUBCATEGORY
        context['DEVICES_PAGE_OPC_UA_SUBCATEGORY'] = DEVICES_PAGE_OPC_UA_SUBCATEGORY
        context['DEVICES_PAGE_OPC_UA_GDS_PUSH_SUBCATEGORY'] = DEVICES_PAGE_OPC_UA_GDS_PUSH_SUBCATEGORY

        return context
