from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0005_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_summary_submitted',
        ),
    ]
