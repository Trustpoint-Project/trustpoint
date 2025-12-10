"""Test cases for help_pages help_section module."""

from django.test import SimpleTestCase
from django.utils.safestring import SafeString

from ..help_section import HelpPage, HelpRow, HelpSection, ValueRenderType


class ValueRenderTypeTests(SimpleTestCase):
    """Test cases for ValueRenderType enum."""

    def test_value_render_type_code(self) -> None:
        """Test that CODE value render type has correct value."""
        assert ValueRenderType.CODE.value == 'code'

    def test_value_render_type_plain(self) -> None:
        """Test that PLAIN value render type has correct value."""
        assert ValueRenderType.PLAIN.value == 'plain'


class HelpRowTests(SimpleTestCase):
    """Test cases for HelpRow dataclass."""

    def test_help_row_creation(self) -> None:
        """Test creating a HelpRow with all fields."""
        row = HelpRow(
            key='Test Key',
            value='Test Value',
            value_render_type=ValueRenderType.CODE,
            hidden=False,
            css_id='test-id',
        )

        assert row.key == 'Test Key'
        assert row.value == 'Test Value'
        assert row.value_render_type == ValueRenderType.CODE
        assert row.hidden is False
        assert row.css_id == 'test-id'

    def test_help_row_default_values(self) -> None:
        """Test HelpRow default values."""
        row = HelpRow(
            key='Test Key',
            value='Test Value',
            value_render_type=ValueRenderType.PLAIN,
        )

        assert row.hidden is False
        assert row.css_id is None

    def test_help_row_with_safe_string(self) -> None:
        """Test HelpRow with SafeString."""
        safe_key = SafeString('<b>Bold Key</b>')
        safe_value = SafeString('<i>Italic Value</i>')

        row = HelpRow(
            key=safe_key,
            value=safe_value,
            value_render_type=ValueRenderType.CODE,
        )

        assert isinstance(row.key, SafeString)
        assert isinstance(row.value, SafeString)


class HelpSectionTests(SimpleTestCase):
    """Test cases for HelpSection dataclass."""

    def test_help_section_creation(self) -> None:
        """Test creating a HelpSection with all fields."""
        rows = [
            HelpRow('Key1', 'Value1', ValueRenderType.CODE),
            HelpRow('Key2', 'Value2', ValueRenderType.PLAIN),
        ]

        section = HelpSection(
            heading='Test Section',
            rows=rows,
            hidden=False,
            css_id='section-id',
        )

        assert section.heading == 'Test Section'
        assert len(section.rows) == 2
        assert section.rows[0].key == 'Key1'
        assert section.hidden is False
        assert section.css_id == 'section-id'

    def test_help_section_default_values(self) -> None:
        """Test HelpSection default values."""
        section = HelpSection(
            heading='Test Section',
            rows=[],
        )

        assert section.hidden is False
        assert section.css_id is None

    def test_help_section_with_safe_string_heading(self) -> None:
        """Test HelpSection with SafeString heading."""
        safe_heading = SafeString('<h2>Section Heading</h2>')

        section = HelpSection(
            heading=safe_heading,
            rows=[],
        )

        assert isinstance(section.heading, SafeString)


class HelpPageTests(SimpleTestCase):
    """Test cases for HelpPage dataclass."""

    def test_help_page_creation(self) -> None:
        """Test creating a HelpPage."""
        sections = [
            HelpSection('Section 1', []),
            HelpSection('Section 2', []),
        ]

        page = HelpPage(
            heading='Test Page',
            sections=sections,
        )

        assert page.heading == 'Test Page'
        assert len(page.sections) == 2
        assert page.sections[0].heading == 'Section 1'

    def test_help_page_with_safe_string_heading(self) -> None:
        """Test HelpPage with SafeString heading."""
        safe_heading = SafeString('<h1>Page Heading</h1>')

        page = HelpPage(
            heading=safe_heading,
            sections=[],
        )

        assert isinstance(page.heading, SafeString)

    def test_help_page_with_complex_structure(self) -> None:
        """Test HelpPage with complex nested structure."""
        rows = [
            HelpRow('Command', 'openssl genrsa', ValueRenderType.CODE),
            HelpRow('Description', 'Generate RSA key', ValueRenderType.PLAIN),
        ]
        sections = [
            HelpSection('Key Generation', rows),
            HelpSection('Certificate Request', []),
        ]
        page = HelpPage('Complete Guide', sections)

        assert page.heading == 'Complete Guide'
        assert len(page.sections) == 2
        assert len(page.sections[0].rows) == 2
        assert page.sections[0].rows[0].value == 'openssl genrsa'
