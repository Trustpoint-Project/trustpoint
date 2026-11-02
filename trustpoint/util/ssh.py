# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Parse and validate pinned SSH server public keys."""

import paramiko
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def parse_ssh_host_key(value: str) -> paramiko.PKey:
    """Read one OpenSSH public key, with an optional trailing comment."""
    message = _('Enter one valid SSH server public key in OpenSSH format.')
    if len(value.strip().splitlines()) != 1:
        raise ValidationError(message)
    try:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(f'server {value.strip()}')
    except (ValueError, paramiko.SSHException, paramiko.hostkeys.InvalidHostKey) as exc:
        raise ValidationError(message) from exc
    if entry is None or entry.key is None:
        raise ValidationError(message)
    return entry.key


def validate_ssh_host_key(value: str) -> None:
    """Validate the public-key model field using the same parser as connections."""
    parse_ssh_host_key(value)
