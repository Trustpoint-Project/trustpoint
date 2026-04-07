from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0003_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='crypto_storage',
            field=models.PositiveSmallIntegerField(choices=[(0, 'Software Storage'), (1, 'HSM Storage')], default=0),
        ),
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='inject_demo_data',
            field=models.BooleanField(default=True, help_text='Inject demo data.'),
        ),
    ]
