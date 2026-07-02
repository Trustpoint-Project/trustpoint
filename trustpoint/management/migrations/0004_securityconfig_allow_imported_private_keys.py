"""Add the Security setting for protected private-key imports."""

from typing import ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    """Add allow_imported_private_keys to SecurityConfig."""

    dependencies: ClassVar[list[tuple[str, str]]] = [
        ('management', '0003_tp_v0_6_0_dev1'),
    ]

    operations: ClassVar[list[object]] = [
        migrations.AddField(
            model_name='securityconfig',
            name='allow_imported_private_keys',
            field=models.BooleanField(
                default=False,
                help_text=(
                    'Allow existing private-key credentials to be imported. Imported keys require '
                    'PKCS#11-backed application-secret protection and are stored encrypted in the database.'
                ),
            ),
        ),
    ]
