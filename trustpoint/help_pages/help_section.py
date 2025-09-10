"""This module contains pydantic classes for help sections."""

import enum
from dataclasses import dataclass

from django.utils.safestring import SafeString

# TODO(AlexHx8472): Check if SafeString should be used instead or additionally for all attributes.  # noqa: FIX002

class ValueRenderType(enum.Enum):
    """Determines how the value part of the list is rendered."""

    CODE = 'code'
    PLAIN = 'plain'


@dataclass
class HelpRow:
    """A single row in a help section."""

    key: str | SafeString
    value: str | SafeString
    value_render_type: ValueRenderType
    hidden: bool = False
    css_id: str | SafeString | None = None


@dataclass
class HelpSection:
    """Contains a section for the help pages."""
    heading: str | SafeString
    rows: list[HelpRow]
    hidden: bool = False
    css_id: str | SafeString | None = None


@dataclass
class HelpPage:
    """Contains all variable data for help pages."""
    heading: str | SafeString
    sections: list[HelpSection]
