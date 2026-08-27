# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Persist the physical PKCS#11 HSM connection independently of its provider."""

from typing import Any

from django.db import migrations, models


def infer_existing_opensc_connections(apps: Any, _schema_editor: Any) -> None:
    """Keep staged OpenSC configurations classified as USB connections."""
    config_model = apps.get_model('setup_wizard', 'SetupWizardConfigModel')
    config_model.objects.filter(fresh_install_pkcs11_module_path__endswith='opensc-pkcs11.so').update(
        fresh_install_pkcs11_connection_type='usb',
        fresh_install_pkcs11_start_pcscd=True,
    )


class Migration(migrations.Migration):
    """Add the PKCS#11 connection type used for runtime service selection."""

    dependencies = [('setup_wizard', '0001_initial')]  # noqa: RUF012

    operations = [  # noqa: RUF012
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_pkcs11_connection_type',
            field=models.CharField(
                choices=[('network', 'Network HSM'), ('usb', 'USB HSM')],
                default='network',
                help_text='Physical connection used by the staged PKCS#11 provider.',
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_pkcs11_start_pcscd',
            field=models.BooleanField(
                default=False,
                help_text='Whether the operational runtime starts its local PC/SC smart-card service.',
            ),
        ),
        migrations.RunPython(infer_existing_opensc_connections, migrations.RunPython.noop),
    ]
