from django.core.management.commands.makemessages import Command as MakeMessagesCommand


class Command(MakeMessagesCommand):
    msgmerge_options = ['-q', '-N', '--backup=none', '--previous', '--update']
