"""Output wrapper for Django management commands.

Provides an adapter between Django's CommandStyle and our OutputWriter protocol.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.core.management.base import OutputWrapper
    from django.core.management.color import Style


class CommandOutputWrapper:
    """Adapter for Django command output to match OutputWriter protocol."""

    def __init__(self, stdout: OutputWrapper, style: Style) -> None:
        """Initialize the output wrapper.

        Args:
            stdout: Django's output wrapper for stdout.
            style: Django's style formatter for colored output.
        """
        self._stdout = stdout
        self._style = style

    def write(self, msg: str) -> None:
        """Write a message to stdout.

        Args:
            msg: The message to write.
        """
        self._stdout.write(msg)

    def success(self, msg: str) -> str:
        """Format a success message with styling.

        Args:
            msg: The message to format.

        Returns:
            The styled message.
        """
        return self._style.SUCCESS(msg)

    def error(self, msg: str) -> str:
        """Format an error message with styling.

        Args:
            msg: The message to format.

        Returns:
            The styled message.
        """
        return self._style.ERROR(msg)

    def warning(self, msg: str) -> str:
        """Format a warning message with styling.

        Args:
            msg: The message to format.

        Returns:
            The styled message.
        """
        return self._style.WARNING(msg)
