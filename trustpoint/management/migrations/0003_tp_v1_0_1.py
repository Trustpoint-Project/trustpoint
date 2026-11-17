# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Bring the released 1.0.0 management schema up to the 1.0.1 state.

This single migration replaces the unreleased 0003-0016 history so fresh installs
and upgrades run one predictable step. Data migrations are kept in their original
relative order.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from html import escape, unescape
from typing import Any

import django.core.validators
import django.db.migrations.operations.special
import django.db.models.deletion
import django.utils.timezone
import management.models.certificate_authentication
import util.ssh
from django.db import migrations, models

GENESIS_HASH = '0' * 64
BACKFILL_BATCH_SIZE = 500


def install_default_user_profile(apps: Any, schema_editor: Any) -> None:
    """Set the default user certificate profile for existing management CA authentication configurations."""
    profiles = apps.get_model('pki', 'CertificateProfileModel').objects.using(schema_editor.connection.alias)
    profile, _created = profiles.get_or_create(
        unique_name='user_client',
        defaults={
            'display_name': 'User Client Certificate',
            'credential_type': 'application',
            'is_default': True,
            'profile_json': {
                'type': 'cert_profile',
                'display_name': 'User Client Certificate',
                'credential_type': 'application',
                'subj': {'cn': {'default': 'trustpoint-client-certificate'}},
                'ext': {
                    'basic_constraints': {'ca': False, 'critical': True},
                    'key_usage': {'digital_signature': True, 'critical': True},
                    'extended_key_usage': {'usages': ['client_auth']},
                },
                'validity': {'days': 365},
            },
        },
    )
    configs = apps.get_model('management', 'CertificateAuthenticationConfig').objects.using(
        schema_editor.connection.alias
    )
    configs.filter(certificate_profile__isnull=True).update(certificate_profile=profile)


def remove_user_profile_domain_default(apps: Any, schema_editor: Any) -> None:
    """Keep the user authentication profile out of automatic device-domain defaults."""
    profiles = apps.get_model('pki', 'CertificateProfileModel').objects.using(schema_editor.connection.alias)
    profiles.filter(unique_name='user_client').update(is_default=False)


def update_message_data(apps: Any, schema_editor: Any, transform: Any) -> None:
    """Apply a text transform to the user-controlled notification data fields."""
    notifications = apps.get_model('management', 'NotificationModel').objects.using(schema_editor.connection.alias)
    for notification in notifications.filter(
        message_type__in=(
            'USER_CERT_EXPIRING',
            'USER_CERT_EXPIRED',
            'API_CRED_EXPIRING',
            'API_CRED_EXPIRED',
            'CRYPTO_BACKEND_UNAVAILABLE',
            'ACCOUNT_LOCKED',
            'WORKFLOW_FAILED',
            'WORKFLOW_APPROVAL_OVERDUE',
        )
    ).iterator():
        data = dict(notification.message_data)
        for key in ('username', 'identifier', 'workflow', 'backend'):
            if isinstance(data.get(key), str):
                data[key] = transform(data[key])
        if data != notification.message_data:
            notifications.filter(pk=notification.pk).update(message_data=data)


def normalize_notifications(apps: Any, schema_editor: Any) -> None:
    """Unify solved status records and move name escaping to HTML rendering."""
    statuses = apps.get_model('management', 'NotificationStatus').objects.using(schema_editor.connection.alias)
    legacy = statuses.filter(status='SOLVED').first()
    if legacy is not None:
        solved, _ = statuses.get_or_create(status='SOLV')
        links = apps.get_model('management', 'NotificationModel').statuses.through.objects.using(
            schema_editor.connection.alias,
        )
        already_solved = links.filter(notificationstatus_id=solved.pk).values('notificationmodel_id')
        links.filter(notificationstatus_id=legacy.pk).exclude(
            notificationmodel_id__in=already_solved,
        ).update(notificationstatus_id=solved.pk)
        legacy.delete(using=schema_editor.connection.alias)
    update_message_data(apps, schema_editor, unescape)


def restore_escaped_data(apps: Any, schema_editor: Any) -> None:
    """Restore the previous HTML-escaped form when the migration is reversed."""
    update_message_data(apps, schema_editor, escape)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    ).encode('utf-8')


def _entry_payload(entry: Any, sequence: int, previous_hash: str, actor_label: str, target_type: str) -> dict[str, Any]:
    timestamp = entry.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=dt.UTC)
    return {
        'v': 1,
        'sequence': sequence,
        'previous_hash': previous_hash,
        'timestamp': timestamp.astimezone(dt.UTC).isoformat(timespec='microseconds'),
        'operation_type': entry.operation_type,
        'target_type': target_type,
        'target_object_id': entry.target_object_id,
        'target_display': entry.target_display,
        'actor_label': actor_label,
        'details': entry.details or {},
    }


def backfill_audit_chain(apps: Any, schema_editor: Any) -> None:
    """Hash existing rows in stable order and anchor the signing configuration row."""
    del schema_editor
    audit_log = apps.get_model('management', 'AuditLog')
    signing_config = apps.get_model('management', 'AuditSigningConfig')

    previous_hash = GENESIS_HASH
    batch: list[Any] = []
    rows = (
        audit_log.objects.select_related('actor', 'target_content_type')
        .order_by('timestamp', 'pk')
        .iterator(chunk_size=BACKFILL_BATCH_SIZE)
    )
    for sequence, entry in enumerate(rows, start=1):
        actor_label = entry.actor.username[:255] if entry.actor_id and entry.actor else ''
        target_type = f'{entry.target_content_type.app_label}.{entry.target_content_type.model}'[:255]
        payload = _entry_payload(entry, sequence, previous_hash, actor_label, target_type)
        entry_hash = hashlib.sha256(_canonical_json(payload)).hexdigest()
        entry.sequence = sequence
        entry.previous_hash = previous_hash
        entry.entry_hash = entry_hash
        entry.actor_label = actor_label
        entry.target_type = target_type
        batch.append(entry)
        previous_hash = entry_hash
        if len(batch) >= BACKFILL_BATCH_SIZE:
            audit_log.objects.bulk_update(
                batch,
                ['sequence', 'previous_hash', 'entry_hash', 'actor_label', 'target_type'],
            )
            batch = []
    if batch:
        audit_log.objects.bulk_update(
            batch,
            ['sequence', 'previous_hash', 'entry_hash', 'actor_label', 'target_type'],
        )
    signing_config.objects.get_or_create(pk=1)


def create_chain_lock(apps: Any, schema_editor: Any) -> None:
    """Create the singleton lock row used to serialize audit appends."""
    del schema_editor
    apps.get_model('management', 'AuditLogChainLock').objects.get_or_create(pk=1)


class Migration(migrations.Migration):
    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        ('management', '0002_initial'),
        ('pki', '0004_add_traceability_credential_type'),
        ('pki', '0006_self_signed_ca_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='backupoptions',
            name='host_key',
            field=models.TextField(
                blank=True,
                default='',
                help_text='Verified OpenSSH server public key (key type and Base64 data, with an optional comment).',
                validators=[util.ssh.validate_ssh_host_key],
                verbose_name='Server host public key',
            ),
        ),
        migrations.CreateModel(
            name='TraceabilityCredentialGenerationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('generation_number', models.PositiveIntegerField()),
                ('status', models.CharField(choices=[('ACTIVE', 'Active'), ('RETIRED', 'Retired')], max_length=8)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activated_at', models.DateTimeField()),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                (
                    'credential',
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='traceability_generation',
                        to='pki.credentialmodel',
                    ),
                ),
            ],
            options={
                'ordering': ['generation_number'],
            },
        ),
        migrations.CreateModel(
            name='TraceabilityCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'assignment_method',
                    models.CharField(
                        choices=[
                            ('MANAGEMENT_CA', 'Issue from Management CA'),
                            ('PKCS12', 'PKCS#12 file'),
                            ('SEPARATE_FILES', 'Separate files'),
                            ('CSR', 'Generate CSR'),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    'management_ca',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='pki.camodel',
                    ),
                ),
                (
                    'pending_credential',
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='pki.credentialmodel',
                    ),
                ),
                ('pending_csr', models.TextField(blank=True, default='')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField(blank=True, default='')),
                (
                    'curve',
                    models.CharField(
                        blank=True,
                        choices=[('1.2.840.10045.3.1.7', 'SECP256R1'), ('1.3.132.0.34', 'SECP384R1')],
                        default='',
                        max_length=64,
                    ),
                ),
                (
                    'status',
                    models.CharField(
                        choices=[('UNASSIGNED', 'Awaiting credential'), ('ACTIVE', 'Active'), ('RETIRED', 'Retired')],
                        default='UNASSIGNED',
                        max_length=10,
                    ),
                ),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('retired_at', models.DateTimeField(blank=True, null=True)),
                (
                    'current_generation',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='management.traceabilitycredentialgenerationmodel',
                    ),
                ),
            ],
            options={
                'ordering': ['-created_at'],
                'constraints': [
                    models.UniqueConstraint(
                        condition=models.Q(('status', 'ACTIVE')),
                        fields=('status',),
                        name='traceability_one_active_credential',
                    )
                ],
            },
        ),
        migrations.AddField(
            model_name='traceabilitycredentialgenerationmodel',
            name='traceability_credential',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name='generations',
                to='management.traceabilitycredentialmodel',
            ),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(
                fields=('traceability_credential', 'generation_number'),
                name='traceability_signing_generation_number_unique',
            ),
        ),
        migrations.AddConstraint(
            model_name='traceabilitycredentialgenerationmodel',
            constraint=models.UniqueConstraint(
                condition=models.Q(('status', 'ACTIVE')),
                fields=('status',),
                name='traceability_signing_one_active_generation',
            ),
        ),
        migrations.RenameField(
            model_name='securityconfig',
            old_name='allow_auto_gen_pki',
            new_name='allow_self_signed_ca_creation',
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='allow_self_signed_ca_creation',
            field=models.BooleanField(
                db_column='allow_auto_gen_pki', default=False, help_text='Allow enabling local self-signed CA creation.'
            ),
        ),
        migrations.AddField(
            model_name='certificateauthenticationconfig',
            name='certificate_profile',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='pki.certificateprofilemodel',
                verbose_name='Default user certificate profile',
            ),
        ),
        migrations.RunPython(
            code=install_default_user_profile,
            reverse_code=django.db.migrations.operations.special.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='certificateauthenticationconfig',
            name='certificate_profile',
            field=models.ForeignKey(
                blank=True,
                default=management.models.certificate_authentication.default_user_certificate_profile,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to='pki.certificateprofilemodel',
                verbose_name='Default user certificate profile',
            ),
        ),
        migrations.RunPython(
            code=remove_user_profile_domain_default,
            reverse_code=django.db.migrations.operations.special.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='notificationmodel',
            name='message_type',
            field=models.CharField(
                choices=[
                    ('C', 'custom'),
                    ('TEST_CA', 'Issuing Ca Test'),
                    ('TEST_DOMAIN', 'Domain Test'),
                    ('TEST_CERT', 'Cert Test'),
                    ('TEST_DEVICE', 'Device Test'),
                    ('POP_TEST_DATA', 'Welcome Populate Test Data'),
                    ('TP_DOCS', 'Trustpoint Documentation'),
                    ('TP_INFO', 'Trustpoint Project Info'),
                    ('WELCOME', 'Welcome Message'),
                    ('SYS_NOT_HEALTHY', 'System Not Healthy'),
                    ('LOG_SIZE_EXCEEDED', 'Log Size Exceeded'),
                    ('BACKUP_OVERDUE', 'Backup Overdue'),
                    ('REQUEST_FAILED', 'Request Failed'),
                    ('VULNERABILITY', 'Vulnerability'),
                    ('CERT_EXPIRING', 'Cert Expiring'),
                    ('CERT_EXPIRED', 'Cert Expired'),
                    ('USER_CERT_EXPIRING', 'User Cert Expiring'),
                    ('USER_CERT_EXPIRED', 'User Cert Expired'),
                    ('API_CRED_EXPIRING', 'Api Credential Expiring'),
                    ('API_CRED_EXPIRED', 'Api Credential Expired'),
                    ('CRYPTO_BACKEND_UNAVAILABLE', 'Crypto Backend Unavailable'),
                    ('ACCOUNT_LOCKED', 'Account Locked'),
                    ('WORKFLOW_FAILED', 'Workflow Failed'),
                    ('WORKFLOW_APPROVAL_OVERDUE', 'Workflow Approval Overdue'),
                    ('BACKUP_FAILED', 'Backup Failed'),
                    ('NOTIFICATION_CHECK_OVERDUE', 'Notification Check Overdue'),
                    ('CA_EXPIRING', 'Issuing Ca Expiring'),
                    ('CA_EXPIRED', 'Issuing Ca Expired'),
                    ('DOMAIN_NO_CA', 'Domain No Issuing Ca'),
                    ('DEV_NOT_ONBRD', 'Device Not Onboarded'),
                    ('DEV_ONBRD_FAIL', 'Device Onboarding Failed'),
                    ('DEV_CERT_REV', 'Device Cert Revoked'),
                    ('WEAK_SIG_ALGO', 'Weak Signature Algorithm'),
                    ('INSUFF_KEY_LEN', 'Insufficient Key Length'),
                    ('WEAK_ECC_CURVE', 'Weak Ecc Curve'),
                    ('CRL_EXPIRING', 'Crl Expiring'),
                    ('CRL_EXPIRED', 'Crl Expired'),
                    ('GDS_PUSH_FAIL', 'Gds Push Failed'),
                    ('SIGN_KEY_EXP', 'Signer Key Expiring'),
                    ('SIGN_KEY_EXPRD', 'Signer Key Expired'),
                    ('TLS_CERT_EXP', 'Tls Cert Expiring'),
                    ('TLS_CERT_EXPRD', 'Tls Cert Expired'),
                ],
                default='C',
                max_length=32,
            ),
        ),
        migrations.RunPython(
            code=normalize_notifications,
            reverse_code=restore_escaped_data,
        ),
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
            field=models.CharField(
                choices=[
                    ('DEVICE_SECRET_CHANGED', 'Device Secret Changed'),
                    ('CREDENTIAL_ISSUED', 'Credential Issued'),
                    ('CREDENTIAL_RENEWED', 'Credential Renewed'),
                    ('CREDENTIAL_REVOKED', 'Credential Revoked'),
                    ('CREDENTIAL_DELETED', 'Credential Deleted'),
                    ('MODEL_CREATED', 'Model Created (Legacy)'),
                    ('MODEL_UPDATED', 'Model Updated (Legacy)'),
                    ('MODEL_DELETED', 'Model Deleted (Legacy)'),
                    ('APPSECRET_BACKEND_CREATED', 'Application Secret Backend Created'),
                    ('APPSECRET_BACKEND_UPDATED', 'Application Secret Backend Updated'),
                    ('APPSECRET_BACKEND_DELETED', 'Application Secret Backend Deleted'),
                    ('APPSECRET_PKCS11_CREATED', 'Application Secret PKCS#11 Configuration Created'),
                    ('APPSECRET_PKCS11_UPDATED', 'Application Secret PKCS#11 Configuration Updated'),
                    ('APPSECRET_PKCS11_DELETED', 'Application Secret PKCS#11 Configuration Deleted'),
                    ('APPSECRET_SOFTWARE_CREATED', 'Application Secret Software Configuration Created'),
                    ('APPSECRET_SOFTWARE_UPDATED', 'Application Secret Software Configuration Updated'),
                    ('APPSECRET_SOFTWARE_DELETED', 'Application Secret Software Configuration Deleted'),
                    ('CRYPTO_PROVIDER_CREATED', 'Crypto Provider Created'),
                    ('CRYPTO_PROVIDER_UPDATED', 'Crypto Provider Updated'),
                    ('CRYPTO_PROVIDER_DELETED', 'Crypto Provider Deleted'),
                    ('CRYPTO_PKCS11_CONFIG_CREATED', 'Crypto PKCS#11 Configuration Created'),
                    ('CRYPTO_PKCS11_CONFIG_UPDATED', 'Crypto PKCS#11 Configuration Updated'),
                    ('CRYPTO_PKCS11_CONFIG_DELETED', 'Crypto PKCS#11 Configuration Deleted'),
                    ('CRYPTO_SOFTWARE_CONFIG_CREATED', 'Crypto Software Configuration Created'),
                    ('CRYPTO_SOFTWARE_CONFIG_UPDATED', 'Crypto Software Configuration Updated'),
                    ('CRYPTO_SOFTWARE_CONFIG_DELETED', 'Crypto Software Configuration Deleted'),
                    ('CRYPTO_REST_CONFIG_CREATED', 'Crypto REST Configuration Created'),
                    ('CRYPTO_REST_CONFIG_UPDATED', 'Crypto REST Configuration Updated'),
                    ('CRYPTO_REST_CONFIG_DELETED', 'Crypto REST Configuration Deleted'),
                    ('SECURITY_CONFIG_CREATED', 'Security Configuration Created'),
                    ('SECURITY_CONFIG_DELETED', 'Security Configuration Deleted'),
                    ('CA_UPDATED', 'CA Updated'),
                    ('TRUSTSTORE_CREATED', 'Truststore Created'),
                    ('TRUSTSTORE_UPDATED', 'Truststore Updated'),
                    ('TRUSTSTORE_DELETED', 'Truststore Deleted'),
                    ('TRUSTSTORE_ENTRY_CREATED', 'Truststore Certificate Created'),
                    ('TRUSTSTORE_ENTRY_UPDATED', 'Truststore Certificate Updated'),
                    ('TRUSTSTORE_ENTRY_DELETED', 'Truststore Certificate Deleted'),
                    ('DOMAIN_UPDATED', 'Domain Updated'),
                    ('DOMAIN_PROFILE_CREATED', 'Domain Certificate Profile Assignment Created'),
                    ('DOMAIN_PROFILE_UPDATED', 'Domain Certificate Profile Assignment Updated'),
                    ('DOMAIN_PROFILE_DELETED', 'Domain Certificate Profile Assignment Deleted'),
                    ('CERT_PROFILE_CREATED', 'Certificate Profile Created'),
                    ('CERT_PROFILE_UPDATED', 'Certificate Profile Updated'),
                    ('CERT_PROFILE_DELETED', 'Certificate Profile Deleted'),
                    ('DEVID_REGISTRATION_CREATED', 'DevID Registration Created'),
                    ('DEVID_REGISTRATION_UPDATED', 'DevID Registration Updated'),
                    ('DEVID_REGISTRATION_DELETED', 'DevID Registration Deleted'),
                    ('AGENT_PROFILE_CREATED', 'Agent Profile Created'),
                    ('AGENT_PROFILE_UPDATED', 'Agent Profile Updated'),
                    ('AGENT_PROFILE_DELETED', 'Agent Profile Deleted'),
                    ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'),
                    ('AUDIT_SIGNING_CONFIG_UPDATED', 'Audit Signing Configuration Updated'),
                    ('DEVICE_ADDED', 'Device Added'),
                    ('DEVICE_DELETED', 'Device Deleted'),
                    ('CA_CREATED', 'CA Created'),
                    ('CA_DELETED', 'CA Deleted'),
                    ('CA_ROLLOVER_PLANNED', 'CA Rollover Planned'),
                    ('CA_ROLLOVER_STARTED', 'CA Rollover Started'),
                    ('CA_ROLLOVER_TRANSITIONED', 'CA Rollover Transitioned'),
                    ('CA_ROLLOVER_COMPLETED', 'CA Rollover Completed'),
                    ('CA_ROLLOVER_CANCELLED', 'CA Rollover Cancelled'),
                    ('DOMAIN_CREATED', 'Domain Created'),
                    ('DOMAIN_DELETED', 'Domain Deleted'),
                    ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'),
                    ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'),
                    ('USER_CREATED', 'User Created'),
                    ('SIGNER_DELETED', 'Signer Deleted'),
                    ('SIGNER_ADDED', 'Signer Added'),
                    ('HASH_SIGNED', 'Hash Signed'),
                    ('ORGANIZATION_UPDATED', 'Organization Changed'),
                    ('CRYPTO_VERIFY_PROVIDER', 'Crypto: Verify Provider'),
                    ('CRYPTO_GENERATE_MANAGED_KEY', 'Crypto: Generate Managed Key'),
                    ('CRYPTO_IMPORT_MANAGED_KEY', 'Crypto: Import Managed Key'),
                    ('CRYPTO_VERIFY_MANAGED_KEY', 'Crypto: Verify Managed Key'),
                    ('CRYPTO_GET_PUBLIC_KEY', 'Crypto: Get Public Key'),
                    ('CRYPTO_SIGN', 'Crypto: Sign'),
                    ('CRYPTO_DESTROY_MANAGED_KEY', 'Crypto: Destroy Managed Key'),
                    ('SCEP_ENROLLMENT', 'SCEP: Enrollment'),
                    ('SCEP_RENEWAL', 'SCEP: Renewal'),
                    ('SCEP_RETRY', 'SCEP: Verified Retry'),
                    ('SCEP_REJECTED', 'SCEP: Request Rejected'),
                    ('SCEP_SECRET_PROVISIONED', 'SCEP: Enrollment Secret Provisioned'),
                ],
                db_index=True,
                max_length=32,
                verbose_name='Operation Type',
            ),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='target_content_type',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                to='contenttypes.contenttype',
                verbose_name='Target Content Type',
            ),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='timestamp',
            field=models.DateTimeField(
                db_index=True, default=django.utils.timezone.now, editable=False, verbose_name='Timestamp'
            ),
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
                (
                    'traceability_credential',
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='audit_checkpoints',
                        to='management.traceabilitycredentialmodel',
                    ),
                ),
                (
                    'traceability_generation',
                    models.ForeignKey(
                        editable=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='audit_checkpoints',
                        to='management.traceabilitycredentialgenerationmodel',
                    ),
                ),
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
                (
                    'enabled',
                    models.BooleanField(
                        default=False,
                        help_text='Sign a checkpoint of the audit hash chain after the configured interval.',
                        verbose_name='Enable audit checkpoint signing',
                    ),
                ),
                (
                    'checkpoint_event_interval',
                    models.PositiveIntegerField(
                        default=100,
                        help_text='Number of new audit events that triggers a signed checkpoint.',
                        validators=[django.core.validators.MinValueValidator(1)],
                        verbose_name='Events per checkpoint',
                    ),
                ),
                (
                    'checkpoint_time_interval_minutes',
                    models.PositiveIntegerField(
                        blank=True,
                        help_text='Sign at least this often when new audit events exist. Leave empty to disable time-based signing.',
                        null=True,
                        validators=[django.core.validators.MinValueValidator(1)],
                        verbose_name='Maximum checkpoint interval (minutes)',
                    ),
                ),
                ('last_signing_attempt_at', models.DateTimeField(blank=True, editable=False, null=True)),
                ('last_signing_error', models.TextField(blank=True, default='', editable=False)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'traceability_credential',
                    models.ForeignKey(
                        blank=True,
                        help_text='The Traceability Credential used for new audit checkpoints.',
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name='+',
                        to='management.traceabilitycredentialmodel',
                        verbose_name='Signing credential',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Audit Log Signing Configuration',
                'verbose_name_plural': 'Audit Log Signing Configuration',
            },
        ),
        migrations.RunPython(
            code=backfill_audit_chain,
            reverse_code=django.db.migrations.operations.special.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='actor_label',
            field=models.CharField(blank=True, default='', editable=False, max_length=255),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='entry_hash',
            field=models.CharField(editable=False, max_length=64, unique=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='previous_hash',
            field=models.CharField(editable=False, max_length=64),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='sequence',
            field=models.PositiveBigIntegerField(editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='target_type',
            field=models.CharField(editable=False, max_length=255),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='operation_type',
            field=models.CharField(
                choices=[
                    ('DEVICE_SECRET_CHANGED', 'Device Secret Changed'),
                    ('CREDENTIAL_ISSUED', 'Credential Issued'),
                    ('CREDENTIAL_RENEWED', 'Credential Renewed'),
                    ('CREDENTIAL_REVOKED', 'Credential Revoked'),
                    ('CREDENTIAL_DELETED', 'Credential Deleted'),
                    ('MODEL_CREATED', 'Model Created (Legacy)'),
                    ('MODEL_UPDATED', 'Model Updated (Legacy)'),
                    ('MODEL_DELETED', 'Model Deleted (Legacy)'),
                    ('APPSECRET_BACKEND_CREATED', 'Application Secret Backend Created'),
                    ('APPSECRET_BACKEND_UPDATED', 'Application Secret Backend Updated'),
                    ('APPSECRET_BACKEND_DELETED', 'Application Secret Backend Deleted'),
                    ('APPSECRET_PKCS11_CREATED', 'Application Secret PKCS#11 Configuration Created'),
                    ('APPSECRET_PKCS11_UPDATED', 'Application Secret PKCS#11 Configuration Updated'),
                    ('APPSECRET_PKCS11_DELETED', 'Application Secret PKCS#11 Configuration Deleted'),
                    ('APPSECRET_SOFTWARE_CREATED', 'Application Secret Software Configuration Created'),
                    ('APPSECRET_SOFTWARE_UPDATED', 'Application Secret Software Configuration Updated'),
                    ('APPSECRET_SOFTWARE_DELETED', 'Application Secret Software Configuration Deleted'),
                    ('CRYPTO_PROVIDER_CREATED', 'Crypto Provider Created'),
                    ('CRYPTO_PROVIDER_UPDATED', 'Crypto Provider Updated'),
                    ('CRYPTO_PROVIDER_DELETED', 'Crypto Provider Deleted'),
                    ('CRYPTO_PKCS11_CONFIG_CREATED', 'Crypto PKCS#11 Configuration Created'),
                    ('CRYPTO_PKCS11_CONFIG_UPDATED', 'Crypto PKCS#11 Configuration Updated'),
                    ('CRYPTO_PKCS11_CONFIG_DELETED', 'Crypto PKCS#11 Configuration Deleted'),
                    ('CRYPTO_SOFTWARE_CONFIG_CREATED', 'Crypto Software Configuration Created'),
                    ('CRYPTO_SOFTWARE_CONFIG_UPDATED', 'Crypto Software Configuration Updated'),
                    ('CRYPTO_SOFTWARE_CONFIG_DELETED', 'Crypto Software Configuration Deleted'),
                    ('CRYPTO_REST_CONFIG_CREATED', 'Crypto REST Configuration Created'),
                    ('CRYPTO_REST_CONFIG_UPDATED', 'Crypto REST Configuration Updated'),
                    ('CRYPTO_REST_CONFIG_DELETED', 'Crypto REST Configuration Deleted'),
                    ('SECURITY_CONFIG_CREATED', 'Security Configuration Created'),
                    ('SECURITY_CONFIG_DELETED', 'Security Configuration Deleted'),
                    ('CA_UPDATED', 'CA Updated'),
                    ('TRUSTSTORE_CREATED', 'Truststore Created'),
                    ('TRUSTSTORE_UPDATED', 'Truststore Updated'),
                    ('TRUSTSTORE_DELETED', 'Truststore Deleted'),
                    ('TRUSTSTORE_ENTRY_CREATED', 'Truststore Certificate Created'),
                    ('TRUSTSTORE_ENTRY_UPDATED', 'Truststore Certificate Updated'),
                    ('TRUSTSTORE_ENTRY_DELETED', 'Truststore Certificate Deleted'),
                    ('DOMAIN_UPDATED', 'Domain Updated'),
                    ('DOMAIN_PROFILE_CREATED', 'Domain Certificate Profile Assignment Created'),
                    ('DOMAIN_PROFILE_UPDATED', 'Domain Certificate Profile Assignment Updated'),
                    ('DOMAIN_PROFILE_DELETED', 'Domain Certificate Profile Assignment Deleted'),
                    ('CERT_PROFILE_CREATED', 'Certificate Profile Created'),
                    ('CERT_PROFILE_UPDATED', 'Certificate Profile Updated'),
                    ('CERT_PROFILE_DELETED', 'Certificate Profile Deleted'),
                    ('DEVID_REGISTRATION_CREATED', 'DevID Registration Created'),
                    ('DEVID_REGISTRATION_UPDATED', 'DevID Registration Updated'),
                    ('DEVID_REGISTRATION_DELETED', 'DevID Registration Deleted'),
                    ('AGENT_PROFILE_CREATED', 'Agent Profile Created'),
                    ('AGENT_PROFILE_UPDATED', 'Agent Profile Updated'),
                    ('AGENT_PROFILE_DELETED', 'Agent Profile Deleted'),
                    ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'),
                    ('AUDIT_SIGNING_CONFIG_UPDATED', 'Audit Signing Configuration Updated'),
                    ('AUDIT_CHECKPOINT_SIGNED', 'Audit Checkpoint Signed'),
                    ('DEVICE_ADDED', 'Device Added'),
                    ('DEVICE_DELETED', 'Device Deleted'),
                    ('CA_CREATED', 'CA Created'),
                    ('CA_DELETED', 'CA Deleted'),
                    ('CA_ROLLOVER_PLANNED', 'CA Rollover Planned'),
                    ('CA_ROLLOVER_STARTED', 'CA Rollover Started'),
                    ('CA_ROLLOVER_TRANSITIONED', 'CA Rollover Transitioned'),
                    ('CA_ROLLOVER_COMPLETED', 'CA Rollover Completed'),
                    ('CA_ROLLOVER_CANCELLED', 'CA Rollover Cancelled'),
                    ('DOMAIN_CREATED', 'Domain Created'),
                    ('DOMAIN_DELETED', 'Domain Deleted'),
                    ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'),
                    ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'),
                    ('USER_CREATED', 'User Created'),
                    ('SIGNER_DELETED', 'Signer Deleted'),
                    ('SIGNER_ADDED', 'Signer Added'),
                    ('HASH_SIGNED', 'Hash Signed'),
                    ('ORGANIZATION_UPDATED', 'Organization Changed'),
                    ('CRYPTO_VERIFY_PROVIDER', 'Crypto: Verify Provider'),
                    ('CRYPTO_GENERATE_MANAGED_KEY', 'Crypto: Generate Managed Key'),
                    ('CRYPTO_IMPORT_MANAGED_KEY', 'Crypto: Import Managed Key'),
                    ('CRYPTO_VERIFY_MANAGED_KEY', 'Crypto: Verify Managed Key'),
                    ('CRYPTO_GET_PUBLIC_KEY', 'Crypto: Get Public Key'),
                    ('CRYPTO_SIGN', 'Crypto: Sign'),
                    ('CRYPTO_DESTROY_MANAGED_KEY', 'Crypto: Destroy Managed Key'),
                    ('SCEP_ENROLLMENT', 'SCEP: Enrollment'),
                    ('SCEP_RENEWAL', 'SCEP: Renewal'),
                    ('SCEP_RETRY', 'SCEP: Verified Retry'),
                    ('SCEP_REJECTED', 'SCEP: Request Rejected'),
                    ('SCEP_SECRET_PROVISIONED', 'SCEP: Enrollment Secret Provisioned'),
                ],
                db_index=True,
                max_length=32,
                verbose_name='Operation Type',
            ),
        ),
        migrations.CreateModel(
            name='AuditLogChainLock',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'verbose_name': 'Audit Log Chain Lock',
                'verbose_name_plural': 'Audit Log Chain Lock',
            },
        ),
        migrations.RunPython(
            code=create_chain_lock,
            reverse_code=django.db.migrations.operations.special.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='target_content_type',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                to='contenttypes.contenttype',
                verbose_name='Target Content Type',
            ),
        ),
    ]
