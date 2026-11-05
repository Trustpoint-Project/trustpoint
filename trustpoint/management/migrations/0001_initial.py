# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import management.models.security
import util.encrypted_fields
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='AccountSecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('api_credential_expiry_days', models.PositiveIntegerField(blank=True, default=None, null=True)),
                ('idle_timeout_minutes', models.PositiveIntegerField(default=30)),
                ('failed_login_attempts', models.PositiveIntegerField(blank=True, default=None, null=True)),
            ],
            options={
                'verbose_name': 'account security configuration',
                'verbose_name_plural': 'account security configuration',
            },
        ),
        migrations.CreateModel(
            name='AppVersion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=17)),
                (
                    'container_id',
                    models.CharField(blank=True, default='', help_text='Container build ID or hash', max_length=64),
                ),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'App Version',
            },
        ),
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(auto_now_add=True, db_index=True, verbose_name='Timestamp')),
                (
                    'operation_type',
                    models.CharField(
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
                ('target_object_id', models.CharField(db_index=True, max_length=255, verbose_name='Target Object ID')),
                (
                    'target_display',
                    models.CharField(
                        help_text='Human-readable label of the affected object at the time of the action, e.g. "DevOwnerID: my-device". Preserved even if the target is later deleted.',
                        max_length=255,
                        verbose_name='Target Display',
                    ),
                ),
                (
                    'details',
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text='Structured non-secret metadata captured for this audit entry.',
                        verbose_name='Details',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Audit Log Entry',
                'verbose_name_plural': 'Audit Log Entries',
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='BackupOptions',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enable_sftp_storage', models.BooleanField(default=False, verbose_name='Use SFTP storage')),
                ('host', models.CharField(blank=True, max_length=255, verbose_name='Host')),
                ('port', models.PositiveIntegerField(blank=True, default=2222, verbose_name='Port')),
                ('user', models.CharField(blank=True, max_length=128, verbose_name='Username')),
                (
                    'auth_method',
                    models.CharField(
                        choices=[('password', 'Password'), ('ssh_key', 'SSH Key')],
                        default='password',
                        max_length=10,
                        verbose_name='Authentication Method',
                    ),
                ),
                (
                    'password',
                    util.encrypted_fields.EncryptedTextField(
                        blank=True,
                        help_text='Password for SFTP, encrypted in the database.',
                        max_length=128,
                        validators=[django.core.validators.MaxLengthValidator(128)],
                        verbose_name='Password',
                    ),
                ),
                (
                    'private_key',
                    util.encrypted_fields.EncryptedTextField(
                        blank=True,
                        help_text='Paste the private key here (PEM).',
                        verbose_name='SSH Private Key (PEM format)',
                    ),
                ),
                (
                    'key_passphrase',
                    util.encrypted_fields.EncryptedTextField(
                        blank=True,
                        help_text='Passphrase for the private key, if any.',
                        max_length=128,
                        validators=[django.core.validators.MaxLengthValidator(128)],
                        verbose_name='Key Passphrase',
                    ),
                ),
                (
                    'remote_directory',
                    models.CharField(
                        blank=True,
                        default='/upload/trustpoint/',
                        help_text='Remote directory (e.g. /backups/) where files should be uploaded. Trailing slash is optional.',
                        max_length=512,
                        verbose_name='Remote Directory',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Backup Option',
            },
        ),
        migrations.CreateModel(
            name='CertificateAuthenticationConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, verbose_name='Enable certificate authentication')),
            ],
            options={
                'verbose_name': 'Certificate authentication configuration',
                'verbose_name_plural': 'Certificate authentication configurations',
            },
        ),
        migrations.CreateModel(
            name='LoggingConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'log_level',
                    models.CharField(
                        choices=[('0', 'Debug'), ('1', 'Info'), ('2', 'Warning'), ('3', 'Error'), ('4', 'Critical')],
                        default='1',
                        max_length=8,
                    ),
                ),
                (
                    'crypto_backend_audit_enabled',
                    models.BooleanField(
                        default=False,
                        help_text='Record sanitized crypto backend operations in the audit log. Secrets, PINs, key material, payload bytes, and signatures are never stored.',
                        verbose_name='Audit crypto backend operations',
                    ),
                ),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='NotificationConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'enabled',
                    models.BooleanField(default=False, help_text='Enable or disable all notifications globally.'),
                ),
                (
                    'notification_cycle_enabled',
                    models.BooleanField(
                        default=False,
                        help_text='Enable automatic periodic notification checks via Django-Q2',
                        verbose_name='Enable Notification Cycle Updates',
                    ),
                ),
                (
                    'notification_cycle_interval_hours',
                    models.FloatField(
                        default=0.0833,
                        help_text='The interval in hours between automatic notification checks (default: 5 minutes)',
                        verbose_name='Notification Cycle Interval (hours)',
                    ),
                ),
                (
                    'last_notification_check_started_at',
                    models.DateTimeField(
                        blank=True,
                        help_text='Timestamp when the last notification check task was started',
                        null=True,
                        verbose_name='Last Notification Check Started',
                    ),
                ),
                (
                    'cert_expiry_warning_days',
                    models.PositiveIntegerField(
                        default=30,
                        help_text="Number of days before a certificate's expiration to trigger a 'Certificate Expiring' warning.",
                    ),
                ),
                (
                    'issuing_ca_expiry_warning_days',
                    models.PositiveIntegerField(
                        default=30,
                        help_text="Number of days before an issuing CA's certificate expiration to trigger a warning.",
                    ),
                ),
                (
                    'crl_expiry_warning_days',
                    models.PositiveIntegerField(
                        default=7,
                        help_text="Number of days before a CRL's expiration to trigger a 'CRL Expiring' warning.",
                    ),
                ),
            ],
            options={
                'verbose_name': 'Notification Configuration',
            },
        ),
        migrations.CreateModel(
            name='NotificationMessageModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('short_description', models.CharField(max_length=255)),
                ('long_description', models.CharField(default='No description provided', max_length=65536)),
            ],
        ),
        migrations.CreateModel(
            name='NotificationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'notification_type',
                    models.CharField(
                        choices=[('SET', 'SETUP'), ('INF', 'INFO'), ('WAR', 'WARNING'), ('CRI', 'CRITICAL')],
                        default='INF',
                        max_length=3,
                    ),
                ),
                (
                    'notification_source',
                    models.CharField(
                        choices=[
                            ('S', 'System'),
                            ('D', 'Domain'),
                            ('E', 'Device'),
                            ('I', 'Issuing CA'),
                            ('C', 'Certificate'),
                        ],
                        default='S',
                        max_length=1,
                    ),
                ),
                (
                    'message_type',
                    models.CharField(
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
                ('message_data', models.JSONField(blank=True, default=dict)),
                ('event', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created at')),
            ],
        ),
        migrations.CreateModel(
            name='NotificationStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'status',
                    models.CharField(
                        choices=[
                            ('NEW', 'New'),
                            ('CONF', 'Confirmed'),
                            ('PROG', 'In Progress'),
                            ('SOLV', 'Solved'),
                            ('NOSOL', 'Not Solved'),
                            ('ESC', 'Escalated'),
                            ('SUS', 'Suspended'),
                            ('REJ', 'Rejected'),
                            ('DEL', 'Deleted'),
                            ('CLO', 'Closed'),
                            ('ACK', 'Acknowledged'),
                            ('FAIL', 'Failed'),
                            ('EXP', 'Expired'),
                            ('PEND', 'Pending'),
                        ],
                        max_length=20,
                        unique=True,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='OrganizationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, default='', max_length=100, verbose_name='Organization Name')),
                (
                    'organization',
                    models.CharField(default='trustpoint', max_length=255, verbose_name='Organization (O)'),
                ),
                (
                    'organization_unit',
                    models.CharField(blank=True, default='', max_length=255, verbose_name='Organization Unit (OU)'),
                ),
                ('country', models.CharField(default='DE', max_length=2, verbose_name='Country (C)')),
                ('state', models.CharField(blank=True, default='', max_length=255, verbose_name='State/Province (ST)')),
                (
                    'locality',
                    models.CharField(blank=True, default='', max_length=255, verbose_name='Locality/City (L)'),
                ),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
            ],
            options={
                'verbose_name': 'Organization Model',
            },
        ),
        migrations.CreateModel(
            name='PasswordPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'require_otp',
                    models.BooleanField(
                        default=False,
                        help_text='Require an authenticator code for every password login. Users without OTP must set it up first.',
                        verbose_name='Require OTP',
                    ),
                ),
                (
                    'minimum_length',
                    models.PositiveIntegerField(default=8, help_text='Minimum number of characters in a password.'),
                ),
                (
                    'prevent_password_reuse',
                    models.BooleanField(
                        default=True,
                        help_text='Require a new password to differ from the immediately preceding password.',
                    ),
                ),
                (
                    'password_expiry_days',
                    models.PositiveIntegerField(
                        blank=True,
                        default=None,
                        help_text='Leave empty to keep passwords valid indefinitely.',
                        null=True,
                    ),
                ),
                (
                    'user_similarity_enabled',
                    models.BooleanField(
                        default=True,
                        help_text='Reject passwords that are too similar to the user information checked by Django.',
                    ),
                ),
                (
                    'max_similarity',
                    models.FloatField(
                        default=0.7,
                        help_text='Similarity threshold from 0.1 to 1.0. Lower values make the check stricter.',
                        validators=[
                            django.core.validators.MinValueValidator(0.1),
                            django.core.validators.MaxValueValidator(1.0),
                        ],
                    ),
                ),
                (
                    'reject_common_passwords',
                    models.BooleanField(default=True, help_text='Reject passwords found in the common-password list.'),
                ),
                (
                    'common_password_list_data',
                    models.BinaryField(
                        blank=True,
                        default=bytes,
                        help_text='Custom common-password list contents in plain text or gzip format, included in database backups.',
                    ),
                ),
                (
                    'common_password_list_name',
                    models.CharField(
                        blank=True,
                        default='',
                        help_text='Original filename of the custom common-password list.',
                        max_length=255,
                    ),
                ),
                (
                    'reject_numeric_passwords',
                    models.BooleanField(default=True, help_text='Reject passwords that consist entirely of digits.'),
                ),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Password Policy',
                'verbose_name_plural': 'Password Policies',
            },
        ),
        migrations.CreateModel(
            name='PrometheusConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'enabled',
                    models.BooleanField(
                        default=False,
                        help_text='When enabled, the /prometheus/metrics endpoint is available for scraping.',
                        verbose_name='Enable Prometheus metrics endpoint',
                    ),
                ),
            ],
            options={
                'verbose_name': 'Prometheus Configuration',
            },
        ),
        migrations.CreateModel(
            name='SecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'security_mode',
                    models.CharField(
                        choices=[
                            ('0', 'Lab / Custom'),
                            ('1', 'Brownfield Compatible'),
                            ('2', 'Industrial Standard'),
                            ('3', 'Hardened Production'),
                            ('4', 'Critical Infrastructure'),
                        ],
                        default='1',
                        max_length=6,
                    ),
                ),
                ('auto_gen_pki', models.BooleanField(default=False)),
                (
                    'auto_gen_pki_key_algorithm',
                    models.CharField(
                        choices=[
                            ('RSA2048SHA256', 'RSA2048'),
                            ('RSA4096SHA256', 'RSA4096'),
                            ('SECP256R1SHA256', 'SECP256R1'),
                            ('MLDSA44', 'ML-DSA-44'),
                            ('MLDSA65', 'ML-DSA-65'),
                            ('MLDSA87', 'ML-DSA-87'),
                        ],
                        default='RSA2048SHA256',
                        max_length=24,
                    ),
                ),
                (
                    'rsa_minimum_key_size',
                    models.PositiveIntegerField(
                        blank=True,
                        default=2048,
                        help_text='Minimum RSA key size in bits that certificates must meet. Set to null to disallow RSA entirely.',
                        null=True,
                    ),
                ),
                (
                    'not_permitted_ecc_curve_oids',
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text='JSON list of ECC curve OIDs (from trustpoint_core.oid.NamedCurve) not permitted at the current security level.',
                    ),
                ),
                (
                    'not_permitted_mldsa_variant_oids',
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text='JSON list of ML-DSA variant OIDs (from trustpoint_core.oid.PublicKeyAlgorithmOid) not permitted at the current security level.',
                    ),
                ),
                (
                    'not_permitted_signature_algorithm_oids',
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text='JSON list of hash algorithm OIDs (from trustpoint_core.oid.HashAlgorithm) not permitted at the current security level.',
                    ),
                ),
                (
                    'max_cert_validity_days',
                    models.PositiveIntegerField(
                        blank=True,
                        default=None,
                        help_text='Maximum certificate validity period in days. Set to null for no limit.',
                        null=True,
                    ),
                ),
                (
                    'max_crl_validity_days',
                    models.PositiveIntegerField(
                        blank=True,
                        default=None,
                        help_text='Maximum CRL validity period in days. Set to null for no limit.',
                        null=True,
                    ),
                ),
                (
                    'credential_ttl_seconds',
                    models.PositiveIntegerField(
                        blank=True,
                        default=None,
                        help_text='Default lifetime in seconds for onboarding credentials and SCEP challenges. Blank means no expiry.',
                        null=True,
                        validators=[django.core.validators.MinValueValidator(1)],
                    ),
                ),
                (
                    'allow_user_defined_device_secrets',
                    models.BooleanField(
                        default=False,
                        help_text='Allow custom device enrollment secrets. Requires an unset credential TTL.',
                    ),
                ),
                (
                    'allow_ca_issuance',
                    models.BooleanField(
                        default=False, help_text='Allow issuance of certificates with BasicConstraints ca=True.'
                    ),
                ),
                (
                    'allow_auto_gen_pki',
                    models.BooleanField(default=False, help_text='Allow enabling the auto-generated PKI feature.'),
                ),
                (
                    'allow_self_signed_ca',
                    models.BooleanField(
                        default=False, help_text='Allow self-signed CAs to be imported with credentials.'
                    ),
                ),
                (
                    'allow_imported_private_keys',
                    models.BooleanField(
                        default=False,
                        help_text='Allow existing private-key credentials to be imported. Imported keys require PKCS#11-backed application-secret protection and are stored encrypted in the database.',
                    ),
                ),
                (
                    'permitted_cmp_hmac_algorithms',
                    models.JSONField(
                        blank=True,
                        default=management.models.security.default_cmp_hmac_algorithms,
                        help_text='Select the HMAC algorithms accepted for CMP shared-secret protection. An empty selection disables CMP shared-secret authentication. OpenSSL uses HMAC-SHA1 by default.',
                        verbose_name='Permitted CMP HMAC algorithms',
                    ),
                ),
                (
                    'permitted_no_onboarding_pki_protocols',
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text='JSON list of allowed NoOnboardingPkiProtocol integer values (bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64).',
                    ),
                ),
                (
                    'permitted_onboarding_protocols',
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, REST_USERNAME_PASSWORD=8, AGENT=9).',
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='SmtpEmailConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'enabled',
                    models.BooleanField(default=False, help_text='Use the configured SMTP server for outbound email.'),
                ),
                ('host', models.CharField(blank=True, max_length=255)),
                ('port', models.PositiveIntegerField(default=587)),
                ('use_tls', models.BooleanField(default=True)),
                ('use_ssl', models.BooleanField(default=False)),
                ('username', models.CharField(blank=True, max_length=255)),
                (
                    'password',
                    util.encrypted_fields.EncryptedTextField(
                        blank=True, max_length=1024, validators=[django.core.validators.MaxLengthValidator(1024)]
                    ),
                ),
                ('timeout_seconds', models.PositiveIntegerField(default=10)),
                ('default_from_email', models.EmailField(default='no-reply.trustpoint@localhost', max_length=254)),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'SMTP Email Configuration',
                'verbose_name_plural': 'SMTP Email Configuration',
            },
        ),
        migrations.CreateModel(
            name='TlsSettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ipv4_address', models.GenericIPAddressField(blank=True, null=True, protocol='IPv4')),
            ],
        ),
        migrations.CreateModel(
            name='WeakECCCurve',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'oid',
                    models.CharField(
                        choices=[
                            ('1.3.132.0.8', 'SECP160R1'),
                            ('1.2.840.10045.3.1.1', 'SECP192R1'),
                            ('1.3.132.0.33', 'SECP224R1'),
                            ('1.3.132.0.10', 'SECP256K1'),
                        ],
                        max_length=64,
                        unique=True,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='WeakSignatureAlgorithm',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'oid',
                    models.CharField(
                        choices=[
                            ('1.2.840.113549.2.5', 'MD5'),
                            ('1.3.14.3.2.26', 'SHA-1'),
                            ('2.16.840.1.101.3.4.2.4', 'SHA-224'),
                        ],
                        max_length=64,
                        unique=True,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name='WorkflowExecutionConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                (
                    'mode',
                    models.CharField(
                        choices=[
                            ('auto', 'Automatic (use worker if available, else inline)'),
                            ('inline', 'Inline (run immediately in web process)'),
                            ('worker', 'Worker (requires dedicated worker process)'),
                        ],
                        default='auto',
                        max_length=16,
                    ),
                ),
                (
                    'worker_stale_after_seconds',
                    models.PositiveIntegerField(
                        default=30,
                        help_text='If last worker heartbeat is older than this, treat worker as unavailable.',
                    ),
                ),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
        ),
    ]
