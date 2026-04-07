from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('setup_wizard', '0006_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AddField(
            model_name='setupwizardconfigmodel',
            name='fresh_install_summary_submitted',
            field=models.BooleanField(default=False, help_text='Whether the summary step was submitted.'),
        ),
    ]
