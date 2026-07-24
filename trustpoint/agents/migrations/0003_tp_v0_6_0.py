import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0002_initial'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='agentassignedprofile',
            unique_together=set(),
        ),
        migrations.AddField(
            model_name='agentassignedprofile',
            name='common_name',
            field=models.CharField(default=django.utils.timezone.now, help_text='The Common Name (CN) for the certificate. Must be unique per agent. Used in the certificate subject and for file paths. Examples: "webserver.example.com", "api-server-443", "backup-service"', max_length=100, verbose_name='Common Name (CN)'),
            preserve_default=False,
        ),
        migrations.AlterUniqueTogether(
            name='agentassignedprofile',
            unique_together={('agent', 'common_name')},
        ),
    ]
