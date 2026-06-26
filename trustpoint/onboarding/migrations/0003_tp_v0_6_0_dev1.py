from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0002_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='onboardingconfigmodel',
            name='onboarding_protocol',
            field=models.PositiveIntegerField(choices=[(0, 'Manual Onboarding'), (1, 'CMP - IDevID'), (2, 'CMP - Shared Secret'), (3, 'EST - IDevID'), (4, 'EST - Username & Password'), (5, 'AOKI'), (6, 'BRSKI'), (7, 'OPC - GDS Push'), (8, 'REST - Username & Password'), (9, 'Agent')], verbose_name='Onboarding Protocol'),
        ),
    ]
