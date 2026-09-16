# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Test cases for the help page CSRF template filter."""

from unittest.mock import patch

from django.template import Context, Template
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils.safestring import SafeString

from ..templatetags.csrf_token_filter import replace_csrf


class ReplaceCsrfFilterTests(SimpleTestCase):
    """Test cases for replacing CSRF placeholders in help page HTML."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.request = RequestFactory().post('/help/')

    @patch('help_pages.templatetags.csrf_token_filter.get_token', return_value='csrf-token-value')
    def test_replaces_placeholder_with_hidden_input(self, mock_get_token) -> None:  # type: ignore[no-untyped-def]
        """Test a placeholder is replaced with the request CSRF token input."""
        result = replace_csrf('<form>CSRF_TOKEN_PLACEHOLDER<button>Go</button></form>', self.request)

        assert isinstance(result, SafeString)
        assert 'CSRF_TOKEN_PLACEHOLDER' not in result
        assert 'name="csrfmiddlewaretoken"' in result
        assert 'value="csrf-token-value"' in result
        mock_get_token.assert_called_once_with(self.request)

    @patch('help_pages.templatetags.csrf_token_filter.get_token')
    def test_value_without_placeholder_is_returned_safe_without_token_lookup(self, mock_get_token) -> None:  # type: ignore[no-untyped-def]
        """Test values without placeholders are marked safe unchanged."""
        result = replace_csrf('<p>No form here</p>', self.request)

        assert isinstance(result, SafeString)
        assert result == '<p>No form here</p>'
        mock_get_token.assert_not_called()

    @patch('help_pages.templatetags.csrf_token_filter.get_token', return_value='csrf-token-value')
    def test_empty_value_is_safe_empty_string(self, mock_get_token) -> None:  # type: ignore[no-untyped-def]
        """Test an empty value stays empty and does not request a token."""
        result = replace_csrf('', self.request)

        assert isinstance(result, SafeString)
        assert result == ''
        mock_get_token.assert_not_called()

    @patch('help_pages.templatetags.csrf_token_filter.get_token', return_value='token<&>')
    def test_csrf_token_value_is_escaped(self, mock_get_token) -> None:  # type: ignore[no-untyped-def]
        """Test the inserted token is escaped before being marked safe."""
        result = replace_csrf('CSRF_TOKEN_PLACEHOLDER', self.request)

        assert 'token&lt;&amp;&gt;' in result
        assert 'token<&>' not in result
        mock_get_token.assert_called_once_with(self.request)

    @override_settings(TEMPLATES=[{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True}])
    def test_filter_can_be_used_from_template(self) -> None:
        """Test the registered filter works through Django's template engine."""
        template = Template('{% load csrf_token_filter %}{{ value|replace_csrf:request }}')

        with patch('help_pages.templatetags.csrf_token_filter.get_token', return_value='template-token'):
            rendered = template.render(
                Context({'value': '<form>CSRF_TOKEN_PLACEHOLDER</form>', 'request': self.request})
            )

        assert 'csrfmiddlewaretoken' in rendered
        assert 'template-token' in rendered