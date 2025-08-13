"""This module contains pydantic classes for help sections."""

import enum
from dataclasses import dataclass
from django.utils.safestring import SafeString



class ValueRenderType(enum.Enum):
    """Determines how the value part of the list is rendered."""

    CODE = 'code'
    PLAIN = 'plain'


@dataclass
class HelpRow:
    """A single row in a help section."""

    key: str
    value: str | SafeString
    value_render_type: ValueRenderType
    hidden: bool = False


@dataclass
class HelpSection:
    """Contains a section for the help pages."""
    heading: str
    rows: list[HelpRow]


@dataclass
class HelpPage:
    """Contains all variable data for help pages."""
    heading: str
    sections: list[HelpSection]
