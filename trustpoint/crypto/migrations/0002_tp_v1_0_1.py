# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

from django.db import migrations, models


def enable_software_key_export(apps, schema_editor):
    """Enable export for existing software configs so TLS keys can be deployed."""
    del schema_editor
    software_config = apps.get_model('crypto', 'CryptoProviderSoftwareConfigModel')
    software_config.objects.filter(allow_exportable_private_keys=False).update(allow_exportable_private_keys=True)


class Migration(migrations.Migration):
    dependencies = [
        ('crypto', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cryptoprovidersoftwareconfigmodel',
            name='allow_exportable_private_keys',
            field=models.BooleanField(
                default=True,
                help_text='Allow exporting extractable software keys, as required for the TLS server key.',
            ),
        ),
        migrations.RunPython(enable_software_key_export, migrations.RunPython.noop),
    ]
