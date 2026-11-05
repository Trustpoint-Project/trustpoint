# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Short alias for the compilemessages command."""

from django.core.management.commands.compilemessages import Command as CompileMessagesCommand


class Command(CompileMessagesCommand):
    """A shorter alias to run compilemessages to compile translation .po files into .mo files."""
