# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.core.validators
import django.db.models.deletion
import management.models.security
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0002_initial'),
        ('pki', '0002_initial'),
    ]

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
            name='PasswordPolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('require_otp', models.BooleanField(default=False, help_text='Require an authenticator code for every password login. Users without OTP must set it up first.', verbose_name='Require OTP')),
                ('minimum_length', models.PositiveIntegerField(default=8, help_text='Minimum number of characters in a password.')),
                ('prevent_password_reuse', models.BooleanField(default=True, help_text='Require a new password to differ from the immediately preceding password.')),
                ('password_expiry_days', models.PositiveIntegerField(blank=True, default=None, help_text='Leave empty to keep passwords valid indefinitely.', null=True)),
                ('user_similarity_enabled', models.BooleanField(default=True, help_text='Reject passwords that are too similar to the user information checked by Django.')),
                ('max_similarity', models.FloatField(default=0.7, help_text='Similarity threshold from 0.1 to 1.0. Lower values make the check stricter.', validators=[django.core.validators.MinValueValidator(0.1), django.core.validators.MaxValueValidator(1.0)])),
                ('reject_common_passwords', models.BooleanField(default=True, help_text='Reject passwords found in the common-password list.')),
                ('common_password_list_data', models.BinaryField(blank=True, default=bytes, help_text='Custom common-password list contents in plain text or gzip format, included in database backups.')),
                ('common_password_list_name', models.CharField(blank=True, default='', help_text='Original filename of the custom common-password list.', max_length=255)),
                ('reject_numeric_passwords', models.BooleanField(default=True, help_text='Reject passwords that consist entirely of digits.')),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'Password Policy',
                'verbose_name_plural': 'Password Policies',
            },
        ),
        migrations.DeleteModel(
            name='InternationalizationConfig',
        ),
        migrations.DeleteModel(
            name='UIConfig',
        ),
        migrations.AddField(
            model_name='securityconfig',
            name='allow_user_defined_device_secrets',
            field=models.BooleanField(default=False, help_text='Allow custom device enrollment secrets. Requires an unset credential TTL.'),
        ),
        migrations.AddField(
            model_name='securityconfig',
            name='credential_ttl_seconds',
            field=models.PositiveIntegerField(blank=True, default=None, help_text='Default lifetime in seconds for onboarding credentials and SCEP challenges. Blank means no expiry.', null=True, validators=[django.core.validators.MinValueValidator(1)]),
        ),
        migrations.AddField(
            model_name='securityconfig',
            name='not_permitted_mldsa_variant_oids',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of ML-DSA variant OIDs (from trustpoint_core.oid.PublicKeyAlgorithmOid) not permitted at the current security level.'),
        ),
        migrations.AddField(
            model_name='securityconfig',
            name='permitted_cmp_hmac_algorithms',
            field=models.JSONField(blank=True, default=management.models.security.default_cmp_hmac_algorithms, help_text='Select the HMAC algorithms accepted for CMP shared-secret protection. An empty selection disables CMP shared-secret authentication. OpenSSL uses HMAC-SHA1 by default.', verbose_name='Permitted CMP HMAC algorithms'),
        ),
        migrations.AlterField(
            model_name='auditlog',
            name='operation_type',
            field=models.CharField(choices=[('DEVICE_SECRET_CHANGED', 'Device Secret Changed'), ('CREDENTIAL_ISSUED', 'Credential Issued'), ('CREDENTIAL_RENEWED', 'Credential Renewed'), ('CREDENTIAL_REVOKED', 'Credential Revoked'), ('CREDENTIAL_DELETED', 'Credential Deleted'), ('MODEL_CREATED', 'Model Created (Legacy)'), ('MODEL_UPDATED', 'Model Updated (Legacy)'), ('MODEL_DELETED', 'Model Deleted (Legacy)'), ('APPSECRET_BACKEND_CREATED', 'Application Secret Backend Created'), ('APPSECRET_BACKEND_UPDATED', 'Application Secret Backend Updated'), ('APPSECRET_BACKEND_DELETED', 'Application Secret Backend Deleted'), ('APPSECRET_PKCS11_CREATED', 'Application Secret PKCS#11 Configuration Created'), ('APPSECRET_PKCS11_UPDATED', 'Application Secret PKCS#11 Configuration Updated'), ('APPSECRET_PKCS11_DELETED', 'Application Secret PKCS#11 Configuration Deleted'), ('APPSECRET_SOFTWARE_CREATED', 'Application Secret Software Configuration Created'), ('APPSECRET_SOFTWARE_UPDATED', 'Application Secret Software Configuration Updated'), ('APPSECRET_SOFTWARE_DELETED', 'Application Secret Software Configuration Deleted'), ('CRYPTO_PROVIDER_CREATED', 'Crypto Provider Created'), ('CRYPTO_PROVIDER_UPDATED', 'Crypto Provider Updated'), ('CRYPTO_PROVIDER_DELETED', 'Crypto Provider Deleted'), ('CRYPTO_PKCS11_CONFIG_CREATED', 'Crypto PKCS#11 Configuration Created'), ('CRYPTO_PKCS11_CONFIG_UPDATED', 'Crypto PKCS#11 Configuration Updated'), ('CRYPTO_PKCS11_CONFIG_DELETED', 'Crypto PKCS#11 Configuration Deleted'), ('CRYPTO_SOFTWARE_CONFIG_CREATED', 'Crypto Software Configuration Created'), ('CRYPTO_SOFTWARE_CONFIG_UPDATED', 'Crypto Software Configuration Updated'), ('CRYPTO_SOFTWARE_CONFIG_DELETED', 'Crypto Software Configuration Deleted'), ('CRYPTO_REST_CONFIG_CREATED', 'Crypto REST Configuration Created'), ('CRYPTO_REST_CONFIG_UPDATED', 'Crypto REST Configuration Updated'), ('CRYPTO_REST_CONFIG_DELETED', 'Crypto REST Configuration Deleted'), ('SECURITY_CONFIG_CREATED', 'Security Configuration Created'), ('SECURITY_CONFIG_DELETED', 'Security Configuration Deleted'), ('CA_UPDATED', 'CA Updated'), ('TRUSTSTORE_CREATED', 'Truststore Created'), ('TRUSTSTORE_UPDATED', 'Truststore Updated'), ('TRUSTSTORE_DELETED', 'Truststore Deleted'), ('TRUSTSTORE_ENTRY_CREATED', 'Truststore Certificate Created'), ('TRUSTSTORE_ENTRY_UPDATED', 'Truststore Certificate Updated'), ('TRUSTSTORE_ENTRY_DELETED', 'Truststore Certificate Deleted'), ('DOMAIN_UPDATED', 'Domain Updated'), ('DOMAIN_PROFILE_CREATED', 'Domain Certificate Profile Assignment Created'), ('DOMAIN_PROFILE_UPDATED', 'Domain Certificate Profile Assignment Updated'), ('DOMAIN_PROFILE_DELETED', 'Domain Certificate Profile Assignment Deleted'), ('CERT_PROFILE_CREATED', 'Certificate Profile Created'), ('CERT_PROFILE_UPDATED', 'Certificate Profile Updated'), ('CERT_PROFILE_DELETED', 'Certificate Profile Deleted'), ('DEVID_REGISTRATION_CREATED', 'DevID Registration Created'), ('DEVID_REGISTRATION_UPDATED', 'DevID Registration Updated'), ('DEVID_REGISTRATION_DELETED', 'DevID Registration Deleted'), ('AGENT_PROFILE_CREATED', 'Agent Profile Created'), ('AGENT_PROFILE_UPDATED', 'Agent Profile Updated'), ('AGENT_PROFILE_DELETED', 'Agent Profile Deleted'), ('SECURITY_CONFIG_CHANGED', 'Security Config Changed'), ('DEVICE_ADDED', 'Device Added'), ('DEVICE_DELETED', 'Device Deleted'), ('CA_CREATED', 'CA Created'), ('CA_DELETED', 'CA Deleted'), ('CA_ROLLOVER_PLANNED', 'CA Rollover Planned'), ('CA_ROLLOVER_STARTED', 'CA Rollover Started'), ('CA_ROLLOVER_TRANSITIONED', 'CA Rollover Transitioned'), ('CA_ROLLOVER_COMPLETED', 'CA Rollover Completed'), ('CA_ROLLOVER_CANCELLED', 'CA Rollover Cancelled'), ('DOMAIN_CREATED', 'Domain Created'), ('DOMAIN_DELETED', 'Domain Deleted'), ('TLS_CERTIFICATE_CHANGED', 'TLS Certificate Changed'), ('TLS_CERTIFICATE_DELETED', 'TLS Certificate Deleted'), ('USER_CREATED', 'User Created'), ('SIGNER_DELETED', 'Signer Deleted'), ('SIGNER_ADDED', 'Signer Added'), ('HASH_SIGNED', 'Hash Signed'), ('ORGANIZATION_UPDATED', 'Organization Changed'), ('CRYPTO_VERIFY_PROVIDER', 'Crypto: Verify Provider'), ('CRYPTO_GENERATE_MANAGED_KEY', 'Crypto: Generate Managed Key'), ('CRYPTO_IMPORT_MANAGED_KEY', 'Crypto: Import Managed Key'), ('CRYPTO_VERIFY_MANAGED_KEY', 'Crypto: Verify Managed Key'), ('CRYPTO_GET_PUBLIC_KEY', 'Crypto: Get Public Key'), ('CRYPTO_SIGN', 'Crypto: Sign'), ('CRYPTO_DESTROY_MANAGED_KEY', 'Crypto: Destroy Managed Key'), ('SCEP_ENROLLMENT', 'SCEP: Enrollment'), ('SCEP_RENEWAL', 'SCEP: Renewal'), ('SCEP_RETRY', 'SCEP: Verified Retry'), ('SCEP_REJECTED', 'SCEP: Request Rejected'), ('SCEP_SECRET_PROVISIONED', 'SCEP: Enrollment Secret Provisioned')], db_index=True, max_length=32, verbose_name='Operation Type'),
        ),
        migrations.AlterField(
            model_name='notificationmodel',
            name='message_type',
            field=models.CharField(choices=[('C', 'custom'), ('TEST_CA', 'Issuing Ca Test'), ('TEST_DOMAIN', 'Domain Test'), ('TEST_CERT', 'Cert Test'), ('TEST_DEVICE', 'Device Test'), ('POP_TEST_DATA', 'Welcome Populate Test Data'), ('TP_DOCS', 'Trustpoint Documentation'), ('TP_INFO', 'Trustpoint Project Info'), ('WELCOME', 'Welcome Message'), ('SYS_NOT_HEALTHY', 'System Not Healthy'), ('LOG_SIZE_EXCEEDED', 'Log Size Exceeded'), ('BACKUP_OVERDUE', 'Backup Overdue'), ('REQUEST_FAILED', 'Request Failed'), ('VULNERABILITY', 'Vulnerability'), ('CERT_EXPIRING', 'Cert Expiring'), ('CERT_EXPIRED', 'Cert Expired'), ('CA_EXPIRING', 'Issuing Ca Expiring'), ('CA_EXPIRED', 'Issuing Ca Expired'), ('DOMAIN_NO_CA', 'Domain No Issuing Ca'), ('DEV_NOT_ONBRD', 'Device Not Onboarded'), ('DEV_ONBRD_FAIL', 'Device Onboarding Failed'), ('DEV_CERT_REV', 'Device Cert Revoked'), ('WEAK_SIG_ALGO', 'Weak Signature Algorithm'), ('INSUFF_KEY_LEN', 'Insufficient Key Length'), ('WEAK_ECC_CURVE', 'Weak Ecc Curve'), ('CRL_EXPIRING', 'Crl Expiring'), ('CRL_EXPIRED', 'Crl Expired'), ('GDS_PUSH_FAIL', 'Gds Push Failed'), ('SIGN_KEY_EXP', 'Signer Key Expiring'), ('SIGN_KEY_EXPRD', 'Signer Key Expired'), ('TLS_CERT_EXP', 'Tls Cert Expiring'), ('TLS_CERT_EXPRD', 'Tls Cert Expired')], default='C', max_length=32),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='auto_gen_pki_key_algorithm',
            field=models.CharField(choices=[('RSA2048SHA256', 'RSA2048'), ('RSA4096SHA256', 'RSA4096'), ('SECP256R1SHA256', 'SECP256R1'), ('MLDSA44', 'ML-DSA-44'), ('MLDSA65', 'ML-DSA-65'), ('MLDSA87', 'ML-DSA-87')], default='RSA2048SHA256', max_length=24),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_no_onboarding_pki_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed NoOnboardingPkiProtocol integer values (bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64).'),
        ),
        migrations.AlterField(
            model_name='securityconfig',
            name='permitted_onboarding_protocols',
            field=models.JSONField(blank=True, default=list, help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, REST_USERNAME_PASSWORD=8, AGENT=9).'),
        ),
        migrations.AddConstraint(
            model_name='securityconfig',
            constraint=models.CheckConstraint(condition=models.Q(('allow_user_defined_device_secrets', False), ('credential_ttl_seconds__isnull', True), _connector='OR'), name='custom_device_secrets_require_no_ttl'),
        ),
        migrations.AddField(
            model_name='certificateauthenticationconfig',
            name='issuing_ca',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='user_authentication_config', to='pki.camodel'),
        ),
    ]
