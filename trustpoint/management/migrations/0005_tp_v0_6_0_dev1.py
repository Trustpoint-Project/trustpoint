from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0004_tp_v0_6_0_dev1'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='operation_type',
            field=models.CharField(choices=[('CREDENTIAL_ISSUED', 'Credential Issued'), ('CREDENTIAL_RENEWED', 'Credential Renewed'), ('CREDENTIAL_REVOKED', 'Credential Revoked'), ('CREDENTIAL_DELETED', 'Credential Deleted'), ('MODEL_CREATED', 'Model Created'), ('MODEL_UPDATED', 'Model Updated'), ('MODEL_DELETED', 'Model Deleted'), ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'), ('DEVICE_ADDED', 'Device Added'), ('DEVICE_DELETED', 'Device Deleted'), ('CA_CREATED', 'CA Created'), ('CA_DELETED', 'CA Deleted'), ('DOMAIN_CREATED', 'Domain Created'), ('DOMAIN_DELETED', 'Domain Deleted'), ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'), ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'), ('USER_CREATED', 'User Created'), ('SIGNER_DELETED', 'Signer Deleted'), ('SIGNER_ADDED', 'Signer Added'), ('HASH_SIGNED', 'Hash Signed')], db_index=True, max_length=32, verbose_name='Operation Type'),
        ),
    ]
