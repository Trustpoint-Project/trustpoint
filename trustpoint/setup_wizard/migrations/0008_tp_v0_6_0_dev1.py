import setup_wizard.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0007_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_dns_names',
            field=models.JSONField(blank=True, default=setup_wizard.models.default_tls_dns_names, help_text='Normalized DNS SAN entries for generated TLS credentials.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_ipv4_addresses',
            field=models.JSONField(blank=True, default=setup_wizard.models.default_tls_ipv4_addresses, help_text='Normalized IPv4 SAN entries for generated TLS credentials.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_ipv6_addresses',
            field=models.JSONField(blank=True, default=setup_wizard.models.default_tls_ipv6_addresses, help_text='Normalized IPv6 SAN entries for generated TLS credentials.'),
        ),
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_mode',
            field=models.CharField(choices=[('generate', 'Generate credential'), ('pkcs12', 'Upload PKCS#12'), ('separate_files', 'Upload separate files')], default='generate', help_text='Selected TLS configuration mode during the fresh-install wizard.', max_length=32),
        ),
    ]
