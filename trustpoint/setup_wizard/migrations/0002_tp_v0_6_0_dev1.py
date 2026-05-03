import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0002_tp_v0_6_0_dev1'),
        ('setup_wizard', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='SetupWizardConfigModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('fresh_install_current_step', models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Crypto-Storage'), (1, 'Demo-Data'), (2, 'TLS-Config'), (3, 'Summary')], default=0)),
                ('fresh_install_crypto_storage_submitted', models.BooleanField(default=False, help_text='Whether the crypto storage step was submitted.')),
                ('fresh_install_demo_data_submitted', models.BooleanField(default=False, help_text='Whether the demo data step was submitted.')),
                ('fresh_install_tls_config_submitted', models.BooleanField(default=False, help_text='Whether the TLS config step was submitted.')),
                ('fresh_install_summary_submitted', models.BooleanField(default=False, help_text='Whether the summary step was submitted.')),
                ('fresh_install_tls_mode', models.CharField(choices=[('generate', 'Generate credential'), ('pkcs12', 'Upload PKCS#12'), ('separate_files', 'Upload separate files')], default='generate', help_text='Selected TLS configuration mode during the fresh-install wizard.', max_length=32)),
                ('crypto_storage', models.PositiveSmallIntegerField(choices=[(0, 'Software Storage'), (1, 'HSM Storage')], default=0)),
                ('inject_demo_data', models.BooleanField(default=True, help_text='Inject demo data.')),
                ('fresh_install_tls_credential', models.ForeignKey(blank=True, help_text='Pending TLS server credential staged during the fresh-install wizard.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.credentialmodel')),
            ],
        ),
        migrations.DeleteModel(
            name='SetupWizardConfigurationModel',
        ),
    ]
