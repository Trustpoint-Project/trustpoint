# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep the CA policy database column compatible with the previous release."""

from typing import Any, ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    """Restore the original column without changing the Python field name or values."""

    dependencies: ClassVar[list[tuple[str, str]]] = [
        ('management', '0005_rename_allow_self_signed_ca_creation'),
    ]

    operations: ClassVar[list[Any]] = [
        migrations.AlterField(
            model_name='securityconfig',
            name='allow_self_signed_ca_creation',
            field=models.BooleanField(
                db_column='allow_auto_gen_pki', default=False, help_text='Allow enabling local self-signed CA creation.'
            ),
        ),
    ]
