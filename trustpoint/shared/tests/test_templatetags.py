"""Test cases for template tags in the shared application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import QueryDict
from django.test import RequestFactory, SimpleTestCase

from shared.templatetags.sort_tags import sort_icon, url_sort

if TYPE_CHECKING:
    from django.http import HttpRequest


class TestUrlSortTag(SimpleTestCase):
    """Test cases for the url_sort template tag."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_url_sort_add_field_ascending(self) -> None:
        """Test url_sort adds a field in ascending order when not present."""
        request: HttpRequest = self.factory.get('/')
        context = {'request': request}
        result = url_sort(context, 'name')
        assert result == '?sort=-name'

    def test_url_sort_toggle_to_ascending(self) -> None:
        """Test url_sort toggles from descending to ascending."""
        request: HttpRequest = self.factory.get('/?sort=-name')
        context = {'request': request}
        result = url_sort(context, 'name')
        assert result == '?sort=name'

    def test_url_sort_toggle_to_descending(self) -> None:
        """Test url_sort toggles from ascending to descending."""
        request: HttpRequest = self.factory.get('/?sort=name')
        context = {'request': request}
        result = url_sort(context, 'name')
        assert result == '?sort=-name'

    def test_url_sort_preserves_other_sort_fields(self) -> None:
        """Test url_sort preserves other sort fields in the querystring."""
        request: HttpRequest = self.factory.get('/?sort=-date&sort=status')
        context = {'request': request}
        result = url_sort(context, 'name')
        assert 'sort=-name' in result
        assert 'sort=-date' in result
        assert 'sort=status' in result

    def test_url_sort_removes_existing_field_when_toggling(self) -> None:
        """Test url_sort removes existing field occurrence when toggling."""
        request: HttpRequest = self.factory.get('/?sort=name&sort=date')
        context = {'request': request}
        result = url_sort(context, 'name')
        # Should have -name (toggled) and date (preserved)
        assert 'sort=-name' in result
        assert 'sort=date' in result
        # Should not have the old 'sort=name'
        assert result.count('sort=name') == 0

    def test_url_sort_with_multiple_fields_descending(self) -> None:
        """Test url_sort with multiple fields, toggling one from descending."""
        request: HttpRequest = self.factory.get('/?sort=-name&sort=-date')
        context = {'request': request}
        result = url_sort(context, 'name')
        # Should toggle name to ascending
        assert 'sort=name' in result
        # Should preserve date
        assert 'sort=-date' in result

    def test_url_sort_with_empty_querystring(self) -> None:
        """Test url_sort with no existing sort parameters."""
        request: HttpRequest = self.factory.get('/')
        context = {'request': request}
        result = url_sort(context, 'status')
        assert result == '?sort=-status'

    def test_url_sort_preserves_non_sort_params(self) -> None:
        """Test url_sort preserves non-sort query parameters."""
        request: HttpRequest = self.factory.get('/?page=2&filter=active')
        context = {'request': request}
        result = url_sort(context, 'name')
        assert 'sort=-name' in result
        assert 'page=2' in result
        assert 'filter=active' in result

    def test_url_sort_with_complex_field_name(self) -> None:
        """Test url_sort with field names containing underscores."""
        request: HttpRequest = self.factory.get('/')
        context = {'request': request}
        result = url_sort(context, 'created_at')
        assert result == '?sort=-created_at'

    def test_url_sort_toggle_complex_field(self) -> None:
        """Test url_sort toggling field with underscores."""
        request: HttpRequest = self.factory.get('/?sort=-created_at')
        context = {'request': request}
        result = url_sort(context, 'created_at')
        assert result == '?sort=created_at'

    def test_url_sort_with_multiple_toggles(self) -> None:
        """Test url_sort behavior with multiple fields being toggled."""
        request: HttpRequest = self.factory.get('/?sort=name&sort=-date&sort=status')
        context = {'request': request}
        # Toggle date from descending to ascending
        result = url_sort(context, 'date')
        assert 'sort=date' in result
        assert 'sort=name' in result
        assert 'sort=status' in result

    def test_url_sort_ordering_priority(self) -> None:
        """Test url_sort places toggled field first in the querystring."""
        request: HttpRequest = self.factory.get('/?sort=date&sort=status')
        context = {'request': request}
        result = url_sort(context, 'name')
        # New field should be first
        params = QueryDict(result[1:])  # Strip the '?'
        sort_list = params.getlist('sort')
        assert sort_list[0] == '-name'


class TestSortIconFilter(SimpleTestCase):
    """Test cases for the sort_icon template filter."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()

    def test_sort_icon_ascending(self) -> None:
        """Test sort_icon returns up arrow for ascending sort."""
        request: HttpRequest = self.factory.get('/?sort=name')
        result = sort_icon(request, 'name')
        assert result == '↑'

    def test_sort_icon_descending(self) -> None:
        """Test sort_icon returns down arrow for descending sort."""
        request: HttpRequest = self.factory.get('/?sort=-name')
        result = sort_icon(request, 'name')
        assert result == '↓'

    def test_sort_icon_no_sort(self) -> None:
        """Test sort_icon returns up arrow when field is not sorted."""
        request: HttpRequest = self.factory.get('/')
        result = sort_icon(request, 'name')
        assert result == '↑'

    def test_sort_icon_different_field_sorted(self) -> None:
        """Test sort_icon returns up arrow when a different field is sorted."""
        request: HttpRequest = self.factory.get('/?sort=-date')
        result = sort_icon(request, 'name')
        assert result == '↑'

    def test_sort_icon_multiple_fields_ascending(self) -> None:
        """Test sort_icon with multiple fields, target field ascending."""
        request: HttpRequest = self.factory.get('/?sort=name&sort=-date')
        result = sort_icon(request, 'name')
        assert result == '↑'

    def test_sort_icon_multiple_fields_descending(self) -> None:
        """Test sort_icon with multiple fields, target field descending."""
        request: HttpRequest = self.factory.get('/?sort=-name&sort=date')
        result = sort_icon(request, 'name')
        assert result == '↓'

    def test_sort_icon_complex_field_name(self) -> None:
        """Test sort_icon with field names containing underscores."""
        request: HttpRequest = self.factory.get('/?sort=-created_at')
        result = sort_icon(request, 'created_at')
        assert result == '↓'

    def test_sort_icon_partial_field_name_match(self) -> None:
        """Test sort_icon does not match partial field names."""
        request: HttpRequest = self.factory.get('/?sort=-name_full')
        result = sort_icon(request, 'name')
        assert result == '↑'

    def test_sort_icon_with_special_characters(self) -> None:
        """Test sort_icon with field names that might have special chars."""
        request: HttpRequest = self.factory.get('/?sort=-field_123')
        result = sort_icon(request, 'field_123')
        assert result == '↓'

    def test_sort_icon_empty_sort_list(self) -> None:
        """Test sort_icon with empty sort parameter."""
        request: HttpRequest = self.factory.get('/?sort=')
        result = sort_icon(request, 'name')
        assert result == '↑'
