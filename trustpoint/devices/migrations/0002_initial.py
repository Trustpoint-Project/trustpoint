import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0001_initial'),
        ('onboarding', '0001_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='devicemodel',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='devices', to='pki.domainmodel', verbose_name='Domain'),
        ),
        migrations.AddField(
            model_name='devicemodel',
            name='no_onboarding_config',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='device', to='onboarding.noonboardingconfigmodel', verbose_name='No Onboarding Config'),
        ),
        migrations.AddField(
            model_name='devicemodel',
            name='onboarding_config',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='device', to='onboarding.onboardingconfigmodel', verbose_name='Onboarding Config'),
        ),
        migrations.AddField(
            model_name='remotedevicecredentialdownloadmodel',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='devices.devicemodel'),
        ),
        migrations.AddField(
            model_name='remotedevicecredentialdownloadmodel',
            name='issued_credential_model',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='pki.issuedcredentialmodel'),
        ),
    ]
