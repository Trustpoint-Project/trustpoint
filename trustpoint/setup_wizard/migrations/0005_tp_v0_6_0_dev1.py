from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0004_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_crypto_storage_submitted',
            field=models.BooleanField(default=False, help_text='Whether the crypto storage step was submitted.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_demo_data_submitted',
            field=models.BooleanField(default=False, help_text='Whether the demo data step was submitted.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_summary_submitted',
            field=models.BooleanField(default=False, help_text='Whether the summary step was submitted.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_config_submitted',
            field=models.BooleanField(default=False, help_text='Whether the TLS config step was submitted.'),
        ),
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_current_step',
            field=models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Crypto-Storage'), (1, 'Demo-Data'), (2, 'TLS-Config'), (3, 'Summary')], default=0),
        ),
    ]
