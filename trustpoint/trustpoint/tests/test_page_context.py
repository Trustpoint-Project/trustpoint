"""Tests for page_context module."""
from typing import Any

from django.test import TestCase
from django.views.generic import TemplateView

from trustpoint.page_context import (
    DEVICES_PAGE_CATEGORY,
    DEVICES_PAGE_DEVICES_SUBCATEGORY,
    DEVICES_PAGE_OPC_UA_SUBCATEGORY,
    PKI_PAGE_CATEGORY,
    PKI_PAGE_DOMAIN_SUBCATEGORY,
    PKI_PAGE_ISSUING_CAS_SUBCATEGORY,
    PageContextMixin,
)


class TestPageContextMixin(TestCase):
    """Test cases for PageContextMixin."""

    def test_get_context_data_without_super(self) -> None:
        """Test get_context_data when no super class has get_context_data."""
        class TestView(PageContextMixin):
            page_category = 'test_category'
            page_name = 'test_name'

        view = TestView()
        context = view.get_context_data(test_key='test_value')
        
        assert context['page_category'] == 'test_category'
        assert context['page_name'] == 'test_name'
        assert context['test_key'] == 'test_value'
        assert context['DEVICES_PAGE_CATEGORY'] == DEVICES_PAGE_CATEGORY
        assert context['DEVICES_PAGE_DEVICES_SUBCATEGORY'] == DEVICES_PAGE_DEVICES_SUBCATEGORY
        assert context['DEVICES_PAGE_OPC_UA_SUBCATEGORY'] == DEVICES_PAGE_OPC_UA_SUBCATEGORY

    def test_get_context_data_with_super(self) -> None:
        """Test get_context_data when super class has get_context_data."""
        class TestView(PageContextMixin, TemplateView):
            page_category = PKI_PAGE_CATEGORY
            page_name = PKI_PAGE_DOMAIN_SUBCATEGORY
            template_name = 'test.html'

        view = TestView()
        context = view.get_context_data()
        
        assert context['page_category'] == PKI_PAGE_CATEGORY
        assert context['page_name'] == PKI_PAGE_DOMAIN_SUBCATEGORY
        assert 'view' in context  # Added by TemplateView

    def test_get_context_data_none_page_category(self) -> None:
        """Test get_context_data when page_category is None."""
        class TestView(PageContextMixin):
            page_category = None
            page_name = 'test_name'

        view = TestView()
        context = view.get_context_data()
        
        assert 'page_category' not in context
        assert context['page_name'] == 'test_name'

    def test_get_context_data_none_page_name(self) -> None:
        """Test get_context_data when page_name is None."""
        class TestView(PageContextMixin):
            page_category = 'test_category'
            page_name = None

        view = TestView()
        context = view.get_context_data()
        
        assert context['page_category'] == 'test_category'
        assert 'page_name' not in context

    def test_get_context_data_both_none(self) -> None:
        """Test get_context_data when both are None."""
        class TestView(PageContextMixin):
            page_category = None
            page_name = None

        view = TestView()
        context = view.get_context_data()
        
        assert 'page_category' not in context
        assert 'page_name' not in context
        # But constants should still be present
        assert context['DEVICES_PAGE_CATEGORY'] == DEVICES_PAGE_CATEGORY

    def test_constants_values(self) -> None:
        """Test that constants have expected values."""
        assert DEVICES_PAGE_CATEGORY == 'devices'
        assert DEVICES_PAGE_DEVICES_SUBCATEGORY == 'devices'
        assert DEVICES_PAGE_OPC_UA_SUBCATEGORY == 'opc_ua_gds'
        assert PKI_PAGE_CATEGORY == 'pki'
        assert PKI_PAGE_DOMAIN_SUBCATEGORY == 'domains'
        assert PKI_PAGE_ISSUING_CAS_SUBCATEGORY == 'issuing_cas'

    def test_get_context_data_with_devices_category(self) -> None:
        """Test get_context_data with devices category."""
        class TestView(PageContextMixin):
            page_category = DEVICES_PAGE_CATEGORY
            page_name = DEVICES_PAGE_DEVICES_SUBCATEGORY

        view = TestView()
        context = view.get_context_data()
        
        assert context['page_category'] == DEVICES_PAGE_CATEGORY
        assert context['page_name'] == DEVICES_PAGE_DEVICES_SUBCATEGORY

    def test_get_context_data_with_pki_category(self) -> None:
        """Test get_context_data with PKI category."""
        class TestView(PageContextMixin):
            page_category = PKI_PAGE_CATEGORY
            page_name = PKI_PAGE_ISSUING_CAS_SUBCATEGORY

        view = TestView()
        context = view.get_context_data()
        
        assert context['page_category'] == PKI_PAGE_CATEGORY
        assert context['page_name'] == PKI_PAGE_ISSUING_CAS_SUBCATEGORY

    def test_get_context_data_preserves_kwargs(self) -> None:
        """Test that kwargs are preserved in the context."""
        class TestView(PageContextMixin):
            page_category = 'test'
            page_name = 'test'

        view = TestView()
        context = view.get_context_data(
            custom_key='custom_value',
            another_key=123
        )
        
        assert context['custom_key'] == 'custom_value'
        assert context['another_key'] == 123
