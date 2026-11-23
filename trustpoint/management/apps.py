# Copyright (c) 2024 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Django Management apps."""

import logging
import time

from django.apps import AppConfig
from django.core.signals import request_started
from django.db import DatabaseError

logger = logging.getLogger(__name__)

LOG_LEVEL_SYNC_INTERVAL_SECONDS = 60
_log_level_synced_at = 0.0


def _load_persisted_log_level(sender: object = None, **_kwargs: object) -> None:
    """Apply the stored log level to this process, at most once per interval."""
    del sender
    global _log_level_synced_at  # noqa: PLW0603 - one timestamp per process.
    now = time.monotonic()
    if now - _log_level_synced_at < LOG_LEVEL_SYNC_INTERVAL_SECONDS:
        return
    _log_level_synced_at = now
    from management.models.logging import apply_persisted_log_level  # noqa: PLC0415

    try:
        apply_persisted_log_level()
    except DatabaseError:
        return


class ManagementConfig(AppConfig):
    """Management application configuration."""

    name = 'management'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self) -> None:
        """Register management signals and load the persisted log level lazily."""
        from django_q.signals import post_spawn, pre_execute  # noqa: PLC0415 - imported after apps load.

        import management.signals  # noqa: F401, PLC0415 - importing connects post_migrate receivers.

        request_started.connect(
            _load_persisted_log_level,
            dispatch_uid='management.logging.request_started',
        )
        post_spawn.connect(
            _load_persisted_log_level,
            dispatch_uid='management.logging.post_spawn',
        )
        pre_execute.connect(
            _load_persisted_log_level,
            dispatch_uid='management.logging.pre_execute',
        )
