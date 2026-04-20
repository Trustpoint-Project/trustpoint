import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('onboarding', '0001_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='noonboardingconfigmodel',
            name='trust_store',
            field=models.ForeignKey(blank=True, help_text='Trust store containing certificates to verify the remote server', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='no_onboarding_configs', to='pki.truststoremodel', verbose_name='Trust Store'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='idevid_trust_store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='idevid_onboarding_configs', to='pki.truststoremodel', verbose_name='IDevID Manufacturer Truststore'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='opc_trust_store',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='opc_onboarding_configs', to='pki.truststoremodel', verbose_name='OPC Server Truststore'),
        ),
        migrations.AddField(
            model_name='onboardingconfigmodel',
            name='trust_store',
            field=models.ForeignKey(blank=True, help_text='Trust store containing certificates to verify the remote server', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='onboarding_configs', to='pki.truststoremodel', verbose_name='Trust Store'),
        ),
    ]