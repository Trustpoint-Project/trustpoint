import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificateprofilemodel',
            name='credential_type',
            field=models.CharField(choices=[('application', 'Application Credential'), ('domain', 'Domain Credential')], default='application', max_length=32),
        ),
        migrations.AddField(
            model_name='domainmodel',
            name='domain_credential_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used for issuing domain credentials. Defaults to "domain_credential".', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='domains_as_credential_profile', to='pki.certificateprofilemodel', verbose_name='Domain Credential Profile'),
        ),
        migrations.AlterField(
            model_name='camodel',
            name='ca_type',
            field=models.IntegerField(blank=True, choices=[(-1, 'Keyless CA'), (0, 'Auto-Generated Root'), (1, 'Auto-Generated'), (2, 'Local-Legacy Software'), (3, 'Local-Managed Backend'), (4, 'Remote-EST-RA'), (5, 'Remote-CMP-RA'), (6, 'Remote-Issuing-EST'), (7, 'Remote-Issuing-CMP')], help_text='Type of CA - KEYLESS for keyless CAs', null=True, verbose_name='CA Type'),
        ),
    ]
