"""Add optional PKCS#11 vendor configuration staging fields."""

from django.db import migrations, models


class Migration(migrations.Migration):
    """Migration for optional setup-wizard PKCS#11 vendor config files."""

    dependencies = [
        ('setup_wizard', '0002_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_pkcs11_config_path',
            field=models.TextField(
                blank=True,
                default='',
                help_text='Optional vendor PKCS#11 configuration file staged during the fresh-install wizard.',
            ),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_pkcs11_config_env_var',
            field=models.CharField(
                blank=True,
                default='',
                help_text='Environment variable that points the PKCS#11 library to the vendor configuration file.',
                max_length=128,
            ),
        ),
    ]
