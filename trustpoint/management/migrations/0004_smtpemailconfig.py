"""Add SMTP email configuration singleton."""

from __future__ import annotations

from typing import ClassVar

from django.db import migrations, models


class Migration(migrations.Migration):
    """Create SMTP email configuration table."""

    dependencies: ClassVar[list[tuple[str, str]]] = [
        ('management', '0003_tp_v0_6_0_dev1'),
    ]

    operations: ClassVar[list[migrations.Operation]] = [
        migrations.CreateModel(
            name='SmtpEmailConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'enabled',
                    models.BooleanField(
                        default=False,
                        help_text='Use the configured SMTP server for outbound email.',
                    ),
                ),
                ('host', models.CharField(blank=True, max_length=255)),
                ('port', models.PositiveIntegerField(default=587)),
                ('use_tls', models.BooleanField(default=True)),
                ('use_ssl', models.BooleanField(default=False)),
                ('username', models.CharField(blank=True, max_length=255)),
                ('password', models.CharField(blank=True, max_length=1024)),
                ('timeout_seconds', models.PositiveIntegerField(default=10)),
                ('default_from_email', models.EmailField(default='no-reply@trustpoint.de', max_length=254)),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'SMTP Email Configuration',
                'verbose_name_plural': 'SMTP Email Configuration',
            },
        ),
    ]
