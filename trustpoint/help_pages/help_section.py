"""This module contains pydantic classes for help sections."""

import enum
from dataclasses import dataclass

from django.utils.safestring import SafeString

# TODO(AlexHx8472): Check if SafeString should be used instead or additionally for all attributes.  # noqa: FIX002


class ValueRenderType(enum.Enum):
    """Determines how the value part of the list is rendered."""

    CODE = 'code'
    PLAIN = 'plain'
    HTML = 'html'


@dataclass
class HelpRow:
    """A single row in a help section.

    The optional ``css_class`` attribute can be used by views to mark rows as belonging to
    a specific platform (e.g. "platform-linux" or "platform-windows"). The template already
    supports this attribute and will add it to the rendered ``class`` attribute when set.
    """

    key: str | SafeString
    value: str | SafeString
    value_render_type: ValueRenderType
    hidden: bool = False
    css_id: str | SafeString | None = None
    css_class: str | SafeString | None = None


@dataclass
class HelpSection:
    """Contains a section for the help pages.

    Similar to :class:`HelpRow`, ``css_class`` allows views to attach additional CSS classes
    to the section container (e.g. for platform-specific display logic).
    """

    heading: str | SafeString
    rows: list[HelpRow]
    hidden: bool = False
    css_id: str | SafeString | None = None
    css_class: str | SafeString | None = None


@dataclass
class HelpPage:
    """Contains all variable data for help pages."""

    heading: str | SafeString
    sections: list[HelpSection]
