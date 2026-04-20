import trustpoint.logger
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AppVersion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(max_length=17)),
                ('container_id', models.CharField(blank=True, default='', help_text='Container build ID or hash', max_length=64)),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
            options={
                'verbose_name': 'App Version',
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
                ('auth_method', models.CharField(choices=[('password', 'Password'), ('ssh_key', 'SSH Key')], default='password', max_length=10, verbose_name='Authentication Method')),
                ('password', models.CharField(blank=True, help_text='Plain-text password for SFTP.', max_length=128, verbose_name='Password')),
                ('private_key', models.TextField(blank=True, help_text='Paste the private key here (PEM).', verbose_name='SSH Private Key (PEM format)')),
                ('key_passphrase', models.CharField(blank=True, help_text='Passphrase for the private key, if any.', max_length=128, verbose_name='Key Passphrase')),
                ('remote_directory', models.CharField(blank=True, default='/upload/trustpoint/', help_text='Remote directory (e.g. /backups/) where files should be uploaded. Trailing slash is optional.', max_length=512, verbose_name='Remote Directory')),
            ],
            options={
                'verbose_name': 'Backup Option',
            },
        ),
        migrations.CreateModel(
            name='KeyStorageConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('storage_type', models.CharField(choices=[('software', 'Software (No Encryption)'), ('softhsm', 'SoftHSM Container'), ('physical_hsm', 'Physical HSM')], default='software', help_text='Type of storage for cryptographic material', max_length=12, verbose_name='Storage Type')),
                ('last_updated', models.DateTimeField(auto_now=True, verbose_name='Last Updated')),
            ],
            options={
                'verbose_name': 'Crypto Storage Configuration',
                'verbose_name_plural': 'Crypto Storage Configurations',
            },
        ),
        migrations.CreateModel(
            name='LoggingConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('log_level', models.CharField(choices=[('0', 'Debug'), ('1', 'Info'), ('2', 'Warning'), ('3', 'Error'), ('4', 'Critical')], default='1', max_length=8)),
                ('last_updated', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='NotificationConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('enabled', models.BooleanField(default=False, help_text='Enable or disable all notifications globally.')),
                ('notification_cycle_enabled', models.BooleanField(default=False, help_text='Enable automatic periodic notification checks via Django-Q2', verbose_name='Enable Notification Cycle Updates')),
                ('notification_cycle_interval_hours', models.FloatField(default=0.0833, help_text='The interval in hours between automatic notification checks (default: 5 minutes)', verbose_name='Notification Cycle Interval (hours)')),
                ('last_notification_check_started_at', models.DateTimeField(blank=True, help_text='Timestamp when the last notification check task was started', null=True, verbose_name='Last Notification Check Started')),
                ('cert_expiry_warning_days', models.PositiveIntegerField(default=30, help_text="Number of days before a certificate's expiration to trigger a 'Certificate Expiring' warning.")),
                ('issuing_ca_expiry_warning_days', models.PositiveIntegerField(default=30, help_text="Number of days before an issuing CA's certificate expiration to trigger a warning.")),
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
                ('notification_type', models.CharField(choices=[('SET', 'SETUP'), ('INF', 'INFO'), ('WAR', 'WARNING'), ('CRI', 'CRITICAL')], default='INF', max_length=3)),
                ('notification_source', models.CharField(choices=[('S', 'System'), ('D', 'Domain'), ('E', 'Device'), ('I', 'Issuing CA'), ('C', 'Certificate')], default='S', max_length=1)),
                ('message_type', models.CharField(choices=[('C', 'custom'), ('TEST_CA', 'Issuing Ca Test'), ('TEST_DOMAIN', 'Domain Test'), ('TEST_CERT', 'Cert Test'), ('TEST_DEVICE', 'Device Test'), ('POP_TEST_DATA', 'Welcome Populate Test Data'), ('TP_DOCS', 'Trustpoint Documentation'), ('TP_INFO', 'Trustpoint Project Info'), ('WELCOME', 'Welcome Message'), ('SYS_NOT_HEALTHY', 'System Not Healthy'), ('VULNERABILITY', 'Vulnerability'), ('CERT_EXPIRING', 'Cert Expiring'), ('CERT_EXPIRED', 'Cert Expired'), ('CA_EXPIRING', 'Issuing Ca Expiring'), ('CA_EXPIRED', 'Issuing Ca Expired'), ('DOMAIN_NO_CA', 'Domain No Issuing Ca'), ('DEV_NOT_ONBRD', 'Device Not Onboarded'), ('DEV_ONBRD_FAIL', 'Device Onboarding Failed'), ('DEV_CERT_REV', 'Device Cert Revoked'), ('WEAK_SIG_ALGO', 'Weak Signature Algorithm'), ('INSUFF_KEY_LEN', 'Insufficient Key Length'), ('WEAK_ECC_CURVE', 'Weak Ecc Curve')], default='C', max_length=32)),
                ('message_data', models.JSONField(blank=True, default=dict)),
                ('event', models.CharField(blank=True, default='', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created at')),
            ],
        ),
        migrations.CreateModel(
            name='NotificationStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('NEW', 'New'), ('CONF', 'Confirmed'), ('PROG', 'In Progress'), ('SOLV', 'Solved'), ('NOSOL', 'Not Solved'), ('ESC', 'Escalated'), ('SUS', 'Suspended'), ('REJ', 'Rejected'), ('DEL', 'Deleted'), ('CLO', 'Closed'), ('ACK', 'Acknowledged'), ('FAIL', 'Failed'), ('EXP', 'Expired'), ('PEND', 'Pending')], max_length=20, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='PKCS11Token',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(help_text='Token label in SoftHSM', max_length=100, unique=True, verbose_name='Label')),
                ('slot', models.PositiveIntegerField(help_text='Slot number in SoftHSM', verbose_name='Slot')),
                ('module_path', models.CharField(default='/usr/lib/libpkcs11-proxy.so', help_text='Path to PKCS#11 module library', max_length=255, verbose_name='Module Path')),
                ('encrypted_dek', models.BinaryField(blank=True, help_text='Symmetric key encrypted by the PKCS#11 private key', max_length=512, null=True, verbose_name='Encrypted Data Encryption Key (DEK)')),
                ('bek_encrypted_dek', models.BinaryField(blank=True, help_text='Symmetric key encrypted by the PKCS#11 private key', max_length=512, null=True, verbose_name='Encrypted Data Encryption Key (DEK)')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
            ],
            options={
                'verbose_name': 'PKCS#11 Token',
                'verbose_name_plural': 'PKCS#11 Tokens',
            },
            bases=(models.Model, trustpoint.logger.LoggerMixin),
        ),
        migrations.CreateModel(
            name='SecurityConfig',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('security_mode', models.CharField(choices=[('0', 'Lab / Development'), ('1', 'Brownfield Compatible'), ('2', 'Industrial Standard'), ('3', 'Hardened Production'), ('4', 'Critical Infrastructure')], default='1', max_length=6)),
                ('auto_gen_pki', models.BooleanField(default=False)),
                ('auto_gen_pki_key_algorithm', models.CharField(choices=[('RSA2048SHA256', 'RSA2048'), ('RSA4096SHA256', 'RSA4096'), ('SECP256R1SHA256', 'SECP256R1')], default='RSA2048SHA256', max_length=24)),
                ('rsa_minimum_key_size', models.PositiveIntegerField(blank=True, default=2048, help_text='Minimum RSA key size in bits that certificates must meet. Set to null to disallow RSA entirely.', null=True)),
                ('not_permitted_ecc_curve_oids', models.JSONField(blank=True, default=list, help_text='JSON list of ECC curve OIDs (from trustpoint_core.oid.NamedCurve) not permitted at the current security level.')),
                ('not_permitted_signature_algorithm_oids', models.JSONField(blank=True, default=list, help_text='JSON list of hash algorithm OIDs (from trustpoint_core.oid.HashAlgorithm) not permitted at the current security level.')),
                ('max_cert_validity_days', models.PositiveIntegerField(blank=True, default=None, help_text='Maximum certificate validity period in days. Set to null for no limit.', null=True)),
                ('max_crl_validity_days', models.PositiveIntegerField(blank=True, default=None, help_text='Maximum CRL validity period in days. Set to null for no limit.', null=True)),
                ('allow_ca_issuance', models.BooleanField(default=False, help_text='Allow issuance of certificates with BasicConstraints ca=True.')),
                ('allow_auto_gen_pki', models.BooleanField(default=False, help_text='Allow enabling the auto-generated PKI feature.')),
                ('allow_self_signed_ca', models.BooleanField(default=False, help_text='Allow self-signed CAs to be imported with credentials.')),
                ('require_physical_hsm', models.BooleanField(default=False, help_text='Require key storage to use a physical HSM (KeyStorageConfig.StorageType.PHYSICAL_HSM).')),
                ('permitted_no_onboarding_pki_protocols', models.JSONField(blank=True, default=list, help_text='JSON list of allowed NoOnboardingPkiProtocol integer values (bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16).')),
                ('permitted_onboarding_protocols', models.JSONField(blank=True, default=list, help_text='JSON list of allowed OnboardingProtocol integer values (MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7).')),
            ],
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
                ('oid', models.CharField(choices=[('1.3.132.0.8', 'SECP160R1'), ('1.2.840.10045.3.1.1', 'SECP192R1'), ('1.3.132.0.33', 'SECP224R1'), ('1.3.132.0.10', 'SECP256K1')], max_length=64, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='WeakSignatureAlgorithm',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oid', models.CharField(choices=[('1.2.840.113549.2.5', 'MD5'), ('1.3.14.3.2.26', 'SHA-1'), ('2.16.840.1.101.3.4.2.4', 'SHA-224')], max_length=64, unique=True)),
            ],
        ),
    ]