# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Trustpoint 1.0 envelope encryption; no pre-1.0 key migration is supported."""

from django.db import migrations, models


def require_fresh_installation(apps, schema_editor):
    """Refuse to discard any existing installation's encryption state."""
    alias = schema_editor.connection.alias
    for name, field in [('AppSecretSoftwareConfigModel', 'raw_dek'), ('AppSecretPkcs11ConfigModel', 'wrapped_dek')]:
        model = apps.get_model('appsecrets', name)
        if model.objects.using(alias).exclude(**{f'{field}__isnull': True}).exists():
            raise RuntimeError('Trustpoint 1.0 requires a fresh database. Migration of pre-1.0 encrypted databases is unsupported.')


class Migration(migrations.Migration):
    dependencies = [('appsecrets', '0001_initial')]
    operations = [
        migrations.RunPython(require_fresh_installation),
        migrations.AddField(model_name='appsecretbackendmodel', name='dek_initialized',
                            field=models.BooleanField(default=False, editable=False)),
        migrations.RemoveField(model_name='appsecretsoftwareconfigmodel', name='raw_dek'),
        migrations.AddField(model_name='appsecretsoftwareconfigmodel', name='wrapped_dek',
                            field=models.BinaryField(blank=True, null=True,
                                  help_text='Versioned DEK wrapped by the external software KEK.')),
    ]
