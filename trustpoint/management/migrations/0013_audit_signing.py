# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('management', '0012_normalize_notification_status_and_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='auditlog',
            name='actor_label',
            field=models.CharField(blank=True, editable=False, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(blank=True, editable=False, max_length=64, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='previous_hash',
            field=models.CharField(blank=True, editable=False, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='sequence',
            field=models.PositiveBigIntegerField(blank=True, editable=False, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='target_type',
            field=models.CharField(blank=True, editable=False, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='operation_type',
            field=models.CharField(choices=[('DEVICE_SECRET_CHANGED', 'Device Secret Changed'), ('CREDENTIAL_ISSUED', 'Credential Issued'), ('CREDENTIAL_RENEWED', 'Credential Renewed'), ('CREDENTIAL_REVOKED', 'Credential Revoked'), ('CREDENTIAL_DELETED', 'Credential Deleted'), ('MODEL_CREATED', 'Model Created (Legacy)'), ('MODEL_UPDATED', 'Model Updated (Legacy)'), ('MODEL_DELETED', 'Model Deleted (Legacy)'), ('APPSECRET_BACKEND_CREATED', 'Application Secret Backend Created'), ('APPSECRET_BACKEND_UPDATED', 'Application Secret Backend Updated'), ('APPSECRET_BACKEND_DELETED', 'Application Secret Backend Deleted'), ('APPSECRET_PKCS11_CREATED', 'Application Secret PKCS#11 Configuration Created'), ('APPSECRET_PKCS11_UPDATED', 'Application Secret PKCS#11 Configuration Updated'), ('APPSECRET_PKCS11_DELETED', 'Application Secret PKCS#11 Configuration Deleted'), ('APPSECRET_SOFTWARE_CREATED', 'Application Secret Software Configuration Created'), ('APPSECRET_SOFTWARE_UPDATED', 'Application Secret Software Configuration Updated'), ('APPSECRET_SOFTWARE_DELETED', 'Application Secret Software Configuration Deleted'), ('CRYPTO_PROVIDER_CREATED', 'Crypto Provider Created'), ('CRYPTO_PROVIDER_UPDATED', 'Crypto Provider Updated'), ('CRYPTO_PROVIDER_DELETED', 'Crypto Provider Deleted'), ('CRYPTO_PKCS11_CONFIG_CREATED', 'Crypto PKCS#11 Configuration Created'), ('CRYPTO_PKCS11_CONFIG_UPDATED', 'Crypto PKCS#11 Configuration Updated'), ('CRYPTO_PKCS11_CONFIG_DELETED', 'Crypto PKCS#11 Configuration Deleted'), ('CRYPTO_SOFTWARE_CONFIG_CREATED', 'Crypto Software Configuration Created'), ('CRYPTO_SOFTWARE_CONFIG_UPDATED', 'Crypto Software Configuration Updated'), ('CRYPTO_SOFTWARE_CONFIG_DELETED', 'Crypto Software Configuration Deleted'), ('CRYPTO_REST_CONFIG_CREATED', 'Crypto REST Configuration Created'), ('CRYPTO_REST_CONFIG_UPDATED', 'Crypto REST Configuration Updated'), ('CRYPTO_REST_CONFIG_DELETED', 'Crypto REST Configuration Deleted'), ('SECURITY_CONFIG_CREATED', 'Security Configuration Created'), ('SECURITY_CONFIG_DELETED', 'Security Configuration Deleted'), ('CA_UPDATED', 'CA Updated'), ('TRUSTSTORE_CREATED', 'Truststore Created'), ('TRUSTSTORE_UPDATED', 'Truststore Updated'), ('TRUSTSTORE_DELETED', 'Truststore Deleted'), ('TRUSTSTORE_ENTRY_CREATED', 'Truststore Certificate Created'), ('TRUSTSTORE_ENTRY_UPDATED', 'Truststore Certificate Updated'), ('TRUSTSTORE_ENTRY_DELETED', 'Truststore Certificate Deleted'), ('DOMAIN_UPDATED', 'Domain Updated'), ('DOMAIN_PROFILE_CREATED', 'Domain Certificate Profile Assignment Created'), ('DOMAIN_PROFILE_UPDATED', 'Domain Certificate Profile Assignment Updated'), ('DOMAIN_PROFILE_DELETED', 'Domain Certificate Profile Assignment Deleted'), ('CERT_PROFILE_CREATED', 'Certificate Profile Created'), ('CERT_PROFILE_UPDATED', 'Certificate Profile Updated'), ('CERT_PROFILE_DELETED', 'Certificate Profile Deleted'), ('DEVID_REGISTRATION_CREATED', 'DevID Registration Created'), ('DEVID_REGISTRATION_UPDATED', 'DevID Registration Updated'), ('DEVID_REGISTRATION_DELETED', 'DevID Registration Deleted'), ('AGENT_PROFILE_CREATED', 'Agent Profile Created'), ('AGENT_PROFILE_UPDATED', 'Agent Profile Updated'), ('AGENT_PROFILE_DELETED', 'Agent Profile Deleted'), ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'), ('AUDIT_SIGNING_CONFIG_UPDATED', 'Audit Signing Configuration Updated'), ('DEVICE_ADDED', 'Device Added'), ('DEVICE_DELETED', 'Device Deleted'), ('CA_CREATED', 'CA Created'), ('CA_DELETED', 'CA Deleted'), ('CA_ROLLOVER_PLANNED', 'CA Rollover Planned'), ('CA_ROLLOVER_STARTED', 'CA Rollover Started'), ('CA_ROLLOVER_TRANSITIONED', 'CA Rollover Transitioned'), ('CA_ROLLOVER_COMPLETED', 'CA Rollover Completed'), ('CA_ROLLOVER_CANCELLED', 'CA Rollover Cancelled'), ('DOMAIN_CREATED', 'Domain Created'), ('DOMAIN_DELETED', 'Domain Deleted'), ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'), ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'), ('USER_CREATED', 'User Created'), ('SIGNER_DELETED', 'Signer Deleted'), ('SIGNER_ADDED', 'Signer Added'), ('HASH_SIGNED', 'Hash Signed'), ('ORGANIZATION_UPDATED', 'Organization Changed'), ('CRYPTO_VERIFY_PROVIDER', 'Crypto: Verify Provider'), ('CRYPTO_GENERATE_MANAGED_KEY', 'Crypto: Generate Managed Key'), ('CRYPTO_IMPORT_MANAGED_KEY', 'Crypto: Import Managed Key'), ('CRYPTO_VERIFY_MANAGED_KEY', 'Crypto: Verify Managed Key'), ('CRYPTO_GET_PUBLIC_KEY', 'Crypto: Get Public Key'), ('CRYPTO_SIGN', 'Crypto: Sign'), ('CRYPTO_DESTROY_MANAGED_KEY', 'Crypto: Destroy Managed Key'), ('SCEP_ENROLLMENT', 'SCEP: Enrollment'), ('SCEP_RENEWAL', 'SCEP: Renewal'), ('SCEP_RETRY', 'SCEP: Verified Retry'), ('SCEP_REJECTED', 'SCEP: Request Rejected'), ('SCEP_SECRET_PROVISIONED', 'SCEP: Enrollment Secret Provisioned')], db_index=True, max_length=32, verbose_name='Operation Type'),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='target_content_type',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='contenttypes.contenttype', verbose_name='Target Content Type'),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='timestamp',
            field=models.DateTimeField(db_index=True, default=django.utils.timezone.now, editable=False, verbose_name='Timestamp'),
        ),
        migrations.CreateModel(
            name='AuditLogCheckpoint',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('checkpoint_number', models.PositiveIntegerField(editable=False, unique=True)),
                ('first_sequence', models.PositiveBigIntegerField(editable=False)),
                ('last_sequence', models.PositiveBigIntegerField(editable=False, unique=True)),
                ('entry_count', models.PositiveBigIntegerField(editable=False)),
                ('head_hash', models.CharField(editable=False, max_length=64)),
                ('previous_checkpoint_hash', models.CharField(blank=True, default='', editable=False, max_length=64)),
                ('payload', models.TextField(editable=False)),
                ('signature', models.BinaryField()),
                ('signature_algorithm', models.CharField(editable=False, max_length=32)),
                ('certificate_fingerprint_sha256', models.CharField(editable=False, max_length=64)),
                ('signed_at', models.DateTimeField(editable=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('traceability_credential', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='audit_checkpoints', to='management.traceabilitycredentialmodel')),
                ('traceability_generation', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='audit_checkpoints', to='management.traceabilitycredentialgenerationmodel')),
            ],
            options={
                'verbose_name': 'Audit Log Checkpoint',
                'verbose_name_plural': 'Audit Log Checkpoints',
                'ordering': ['checkpoint_number'],
            },
        ),
        migrations.CreateModel(
            name='AuditSigningConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, help_text='Sign a checkpoint of the audit hash chain after the configured interval.', verbose_name='Enable audit checkpoint signing')),
                ('checkpoint_event_interval', models.PositiveIntegerField(default=100, help_text='Number of new audit events that triggers a signed checkpoint.', validators=[django.core.validators.MinValueValidator(1)], verbose_name='Events per checkpoint')),
                ('checkpoint_time_interval_minutes', models.PositiveIntegerField(blank=True, help_text='Sign at least this often when new audit events exist. Leave empty to disable time-based signing.', null=True, validators=[django.core.validators.MinValueValidator(1)], verbose_name='Maximum checkpoint interval (minutes)')),
                ('last_signing_attempt_at', models.DateTimeField(blank=True, editable=False, null=True)),
                ('last_signing_error', models.TextField(blank=True, default='', editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('traceability_credential', models.ForeignKey(blank=True, help_text='The Traceability Credential used for new audit checkpoints.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='management.traceabilitycredentialmodel', verbose_name='Signing credential')),
            ],
            options={
                'verbose_name': 'Audit Log Signing Configuration',
                'verbose_name_plural': 'Audit Log Signing Configuration',
            },
        ),
    ]
