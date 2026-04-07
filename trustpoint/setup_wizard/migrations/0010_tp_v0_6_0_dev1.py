from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0009_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_dns_names',
        ),
        migrations.RemoveField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_ipv4_addresses',
        ),
        migrations.RemoveField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_ipv6_addresses',
        ),
    ]
