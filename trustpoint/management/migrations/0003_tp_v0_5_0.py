import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('management', '0002_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_no_onboarding_pki_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed NoOnboardingPkiProtocol integer values (bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32).'),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_onboarding_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, REST_USERNAME_PASSWORD=8).'),
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Timestamp')),
                ('operation_type', models.CharField(choices=[('CREDENTIAL_ISSUED', 'Credential Issued'), ('CREDENTIAL_RENEWED', 'Credential Renewed'), ('CREDENTIAL_REVOKED', 'Credential Revoked'), ('CREDENTIAL_DELETED', 'Credential Deleted'), ('MODEL_CREATED', 'Model Created'), ('MODEL_UPDATED', 'Model Updated'), ('MODEL_DELETED', 'Model Deleted'), ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'), ('DEVICE_ADDED', 'Device Added'), ('DEVICE_DELETED', 'Device Deleted'), ('CA_CREATED', 'CA Created'), ('CA_DELETED', 'CA Deleted'), ('DOMAIN_CREATED', 'Domain Created'), ('DOMAIN_DELETED', 'Domain Deleted'), ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'), ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'), ('USER_CREATED', 'User Created')], db_index=True, max_length=32, verbose_name='Operation Type')),
                ('target_object_id', models.CharField(db_index=True, max_length=255, verbose_name='Target Object ID')),
                ('target_display', models.CharField(help_text='Human-readable label of the affected object at the time of the action, e.g. "DevOwnerID: my-device". Preserved even if the target is later deleted.', max_length=255, verbose_name='Target Display')),
                ('actor', models.ForeignKey(blank=True, help_text='The user who triggered the action. Null for system-triggered actions.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_log_entries', to=settings.AUTH_USER_MODEL, verbose_name='Actor')),
                ('target_content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype', verbose_name='Target Content Type')),
            ],
            options={
                'verbose_name': 'Audit Log Entry',
                'verbose_name_plural': 'Audit Log Entries',
                'ordering': ['-timestamp'],
                'indexes': [models.Index(fields=['target_content_type', 'target_object_id'], name='audit_log_target_idx')],
            },
        ),
    ]
