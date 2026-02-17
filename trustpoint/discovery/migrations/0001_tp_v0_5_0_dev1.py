import django.db.models.deletion
from django.db import migrations, models

def add_default_ports(apps, schema_editor):
    DiscoveryPort = apps.get_model('discovery', 'DiscoveryPort')
    defaults = [(80, 'HTTP'), (443, 'HTTPS'), (4840, 'OPC UA')]
    for port, desc in defaults:
        DiscoveryPort.objects.get_or_create(port_number=port, description=desc)

class Migration(migrations.Migration):
    initial = True
    dependencies = [
        ('pki', '0003_tp_v0_5_0_dev1'), # Correct link to the new PKI structure
    ]
    operations = [
        migrations.CreateModel(
            name='DiscoveryPort',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port_number', models.PositiveIntegerField(unique=True)),
                ('description', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='DiscoveredDevice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(unique=True)),
                ('hostname', models.CharField(blank=True, default='', max_length=255)),
                ('open_ports', models.JSONField(blank=True, default=list)),
                ('ssl_info', models.JSONField(blank=True, default=dict, null=True)),
                ('last_seen', models.DateTimeField(auto_now=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('certificate_record', models.ForeignKey(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name='discovered_on_devices', to='pki.certificatemodel')),
            ],
        ),
        # Seed the ports so Florian can run the scan immediately
        migrations.RunPython(add_default_ports),
    ]