"""Management command for make message."""

from django.core.management.commands.makemessages import Command as MakeMessagesCommand


class Command(MakeMessagesCommand):
    """Make message command."""
    msgmerge_options = ['-q', '-N', '--backup=none', '--previous', '--update']
