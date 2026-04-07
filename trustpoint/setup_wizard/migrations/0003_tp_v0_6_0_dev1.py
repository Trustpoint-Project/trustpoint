from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0002_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_current_step',
            field=models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Crypto-Storage'), (1, 'Demo-Data'), (2, 'TLS-Config'), (3, 'Summary')], default=3),
        ),
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='crypto_storage',
            field=models.PositiveSmallIntegerField(blank=True, choices=[(0, 'Software Storage'), (1, 'HSM Storage')], default=0),
        ),
        migrations.AlterField(
            model_name='setupwizardconfigmodel',
            name='inject_demo_data',
            field=models.BooleanField(blank=True, default=True, help_text='Inject demo data.'),
        ),
    ]
