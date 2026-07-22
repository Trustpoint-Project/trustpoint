import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('discovery', '0001_initial'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='discovereddevice',
            name='certificate_record',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='discovered_on_devices', to='pki.certificatemodel'),
        ),
    ]
