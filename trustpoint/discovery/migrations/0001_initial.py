from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    initial = True

    dependencies = [
        # This assumes the pki app has its initial migration ready
        ('pki', '0001_initial'), 
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
                ('certificate_record', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='discovered_on_devices', to='pki.CertificateModel')),
            ],
        ),
    ]