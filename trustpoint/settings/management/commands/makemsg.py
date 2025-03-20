"""Custom Django management command for making message files."""

from typing import Any

from django.core.management.commands.makemessages import Command as MakeMessagesCommand


class Command(MakeMessagesCommand):
    """Custom command extending the `makemessages` command with additional options."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the command with custom `msgmerge_options`."""
        super().__init__(*args, **kwargs)
        self.msgmerge_options = ['-q', '-N', '--backup=none', '--previous', '--update']
