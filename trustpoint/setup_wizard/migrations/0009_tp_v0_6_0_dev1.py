import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0002_tp_v0_6_0_dev1'),
        ('setup_wizard', '0008_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_tls_credential',
            field=models.ForeignKey(blank=True, help_text='Pending TLS server credential staged during the fresh-install wizard.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='pki.credentialmodel'),
        ),
    ]
