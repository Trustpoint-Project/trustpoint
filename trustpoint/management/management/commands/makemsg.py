# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Short alias for the makemessages command."""

from django.core.management.commands.makemessages import Command as MakeMessagesCommand


class Command(MakeMessagesCommand):
    """A shorter alias to run makemessages with quieter msgmerge options."""

    msgmerge_options = ['-q', '-N', '--backup=none', '--previous', '--update']  # noqa: RUF012
