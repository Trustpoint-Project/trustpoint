"""Management command for compile message."""

from django.core.management.commands.compilemessages import Command as CompileMessagesCommand


class Command(CompileMessagesCommand):
    """A shorter alias to run compilemessages to compile translation .po files into .mo files."""
