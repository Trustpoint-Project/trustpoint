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
    ]
