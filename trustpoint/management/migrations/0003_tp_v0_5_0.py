from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_no_onboarding_pki_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed NoOnboardingPkiProtocol integer values (bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32).'),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_onboarding_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, REST_USERNAME_PASSWORD=8).'),
        ),
    ]
