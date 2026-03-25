from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0003_tp_v0_6_0_dev2'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='agentassignedprofile',
            name='certificate_profile',
        ),
        migrations.RemoveField(
            model_name='agentassignedprofile',
            name='push_requested',
        ),
    ]
