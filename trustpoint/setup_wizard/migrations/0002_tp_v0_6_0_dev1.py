from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='SetupWizardConfigModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('crypto_storage', models.PositiveSmallIntegerField(choices=[(0, 'Software Storage'), (1, 'HSM Storage')], default=0)),
                ('inject_demo_data', models.BooleanField(default=True, help_text='Inject demo data.')),
            ],
        ),
        migrations.DeleteModel(
            name='SetupWizardConfigurationModel',
        ),
    ]
