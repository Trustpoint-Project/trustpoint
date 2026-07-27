# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.core.management.commands.makemessages import Command as MakeMessagesCommand


class Command(MakeMessagesCommand):
    msgmerge_options = ['-q', '-N', '--backup=none', '--previous', '--update']
