import django.db.models.deletion
import pki.models.extension
import trustpoint.logger
import util.db
import util.encrypted_fields
import util.field
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('onboarding', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AccessDescriptionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('access_method', models.CharField(editable=False, max_length=256, verbose_name='Access Method OID')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='ActiveTrustpointTlsServerCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
        ),
        migrations.CreateModel(
            name='AuthorityKeyIdentifierExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_identifier', models.CharField(blank=True, editable=False, max_length=256, null=True, verbose_name='Key Identifier')),
                ('authority_cert_serial_number', models.CharField(blank=True, editable=False, max_length=256, null=True, verbose_name='Authority Cert Serial Number')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='CaRolloverModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.CharField(choices=[('planned', 'Planned'), ('awaiting_new_ca', 'Awaiting New CA'), ('preparation', 'Preparation'), ('transition', 'Transition'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='planned', max_length=20, verbose_name='State')),
                ('strategy_type', models.CharField(choices=[('import_ca', 'Import new Issuing CA from file'), ('generate_keypair', 'Generate keypair and request certificate'), ('remote_ca', 'Configure a remote Issuing CA')], help_text='How the new Issuing CA is provisioned.', max_length=20, verbose_name='Strategy')),
                ('planned_at', models.DateTimeField(auto_now_add=True, verbose_name='Planned At')),
                ('started_at', models.DateTimeField(blank=True, null=True, verbose_name='Started At')),
                ('completed_at', models.DateTimeField(blank=True, null=True, verbose_name='Completed At')),
                ('transition_scheduled_at', models.DateTimeField(blank=True, help_text='When the rollover should automatically move from Preparation to Transition phase.', null=True, verbose_name='Scheduled Transition Time')),
                ('notes', models.TextField(blank=True, default='', verbose_name='Notes')),
            ],
            options={
                'verbose_name': 'CA Rollover',
                'verbose_name_plural': 'CA Rollovers',
                'ordering': ['-planned_at'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='CertificateChainOrderModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveIntegerField(editable=False)),
            ],
            options={
                'ordering': ['order'],
            },
        ),
        migrations.CreateModel(
            name='CertificateModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_self_signed', models.BooleanField(verbose_name='Self-Signed')),
                ('common_name', models.CharField(default='', max_length=256, verbose_name='Common Name')),
                ('sha256_fingerprint', models.CharField(editable=False, max_length=256, unique=True, verbose_name='Fingerprint (SHA256)')),
                ('signature_algorithm_oid', models.CharField(choices=[('1.2.840.113549.1.1.4', 'Rsa Md5'), ('1.2.840.113549.1.1.5', 'Rsa Sha1'), ('1.3.14.3.2.29', 'Rsa Sha1 Alt'), ('1.2.840.113549.1.1.14', 'Rsa Sha224'), ('1.2.840.113549.1.1.11', 'Rsa Sha256'), ('1.2.840.113549.1.1.12', 'Rsa Sha384'), ('1.2.840.113549.1.1.13', 'Rsa Sha512'), ('2.16.840.1.101.3.4.3.13', 'Rsa Sha3 224'), ('2.16.840.1.101.3.4.3.14', 'Rsa Sha3 256'), ('2.16.840.1.101.3.4.3.15', 'Rsa Sha3 384'), ('2.16.840.1.101.3.4.3.16', 'Rsa Sha3 512'), ('1.2.840.10045.4.1', 'Ecdsa Sha1'), ('1.2.840.10045.4.3.1', 'Ecdsa Sha224'), ('1.2.840.10045.4.3.2', 'Ecdsa Sha256'), ('1.2.840.10045.4.3.3', 'Ecdsa Sha384'), ('1.2.840.10045.4.3.4', 'Ecdsa Sha512'), ('2.16.840.1.101.3.4.3.9', 'Ecdsa Sha3 224'), ('2.16.840.1.101.3.4.3.10', 'Ecdsa Sha3 256'), ('2.16.840.1.101.3.4.3.11', 'Ecdsa Sha3 384'), ('2.16.840.1.101.3.4.3.12', 'Ecdsa Sha3 512'), ('1.2.840.113533.7.66.13', 'Password Based Mac')], editable=False, max_length=256, verbose_name='Signature Algorithm OID')),
                ('signature_value', models.CharField(editable=False, max_length=65536, verbose_name='Signature Value')),
                ('version', models.PositiveSmallIntegerField(choices=[(2, 'Version 3')], editable=False, verbose_name='Version')),
                ('serial_number', models.CharField(editable=False, max_length=256, verbose_name='Serial Number')),
                ('issuer_public_bytes', models.CharField(editable=False, max_length=2048, verbose_name='Issuer Public Bytes')),
                ('not_valid_before', models.DateTimeField(editable=False, verbose_name='Not Valid Before (UTC)')),
                ('not_valid_after', models.DateTimeField(editable=False, verbose_name='Not Valid After (UTC)')),
                ('subject_public_bytes', models.CharField(editable=False, max_length=2048, verbose_name='Subject Public Bytes')),
                ('spki_algorithm_oid', models.CharField(choices=[('1.2.840.10045.2.1', 'Ecc'), ('1.2.840.113549.1.1.1', 'Rsa')], editable=False, max_length=256, verbose_name='Public Key Algorithm OID')),
                ('spki_algorithm', models.CharField(editable=False, max_length=256, verbose_name='Public Key Algorithm')),
                ('spki_key_size', models.PositiveIntegerField(editable=False, verbose_name='Public Key Size')),
                ('spki_ec_curve_oid', models.CharField(choices=[('', 'None'), ('1.2.840.10045.3.1.1', 'Secp192R1'), ('1.3.132.0.33', 'Secp224R1'), ('1.3.132.0.10', 'Secp256K1'), ('1.2.840.10045.3.1.7', 'Secp256R1'), ('1.3.132.0.34', 'Secp384R1'), ('1.3.132.0.35', 'Secp521R1'), ('1.3.36.3.3.2.8.1.1.7', 'Brainpoolp256R1'), ('1.3.36.3.3.2.8.1.1.11', 'Brainpoolp384R1'), ('1.3.36.3.3.2.8.1.1.13', 'Brainpoolp512R1')], default='', editable=False, max_length=256, verbose_name='Public Key Curve OID (ECC)')),
                ('spki_ec_curve', models.CharField(default=None, editable=False, max_length=256, verbose_name='Public Key Curve (ECC)')),
                ('cert_pem', models.TextField(editable=False, verbose_name='Certificate (PEM)')),
                ('public_key_pem', models.CharField(editable=False, max_length=65536, verbose_name='Public Key (PEM, SPKI)')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created-At')),
            ],
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='CertificatePoliciesExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='CertificateProfileModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=255, unique=True)),
                ('display_name', models.CharField(blank=True, default='', max_length=255)),
                ('credential_type', models.CharField(choices=[('application', 'Application Credential'), ('domain', 'Domain Credential')], default='application', max_length=32)),
                ('profile_json', models.JSONField()),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created-At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated-At')),
                ('is_default', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='CPSUriModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cps_uri', models.CharField(editable=False, max_length=2048, verbose_name='CPS URI')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='CredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('credential_type', models.IntegerField(choices=[(0, 'Trustpoint TLS Server'), (1, 'Root CA'), (2, 'Issuing CA'), (3, 'Issued Credential'), (4, 'DevOwnerID'), (5, 'Signer')], verbose_name='Credential Type')),
                ('private_key', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=9500, verbose_name='Private key (PEM)')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
            ],
            options={
                'abstract': False,
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='CrlDistributionPointsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='CrlModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('crl_pem', models.TextField(help_text='The Certificate Revocation List in PEM format', verbose_name='CRL in PEM format')),
                ('crl_number', models.PositiveBigIntegerField(blank=True, help_text='The CRL number from the CRL extension', null=True, verbose_name='CRL Number')),
                ('this_update', models.DateTimeField(help_text='The thisUpdate field from the CRL', verbose_name='This Update')),
                ('next_update', models.DateTimeField(blank=True, help_text='The nextUpdate field from the CRL', null=True, verbose_name='Next Update')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this is the current active CRL for the CA', verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
            ],
            options={
                'verbose_name': 'Certificate Revocation List',
                'verbose_name_plural': 'Certificate Revocation Lists',
                'ordering': ['-this_update'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='DevIdRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Unique Name')),
                ('serial_number_pattern', models.CharField(help_text='A regex pattern to match valid serial numbers for this registration.', max_length=255, verbose_name='Serial Number Pattern')),
            ],
        ),
        migrations.CreateModel(
            name='DistributionPointModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reasons', models.CharField(blank=True, max_length=16, null=True, verbose_name='Reasons')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='DistributionPointName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='DomainAllowedCertificateProfileModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alias', models.CharField(default='', max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='DomainModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Domain Name')),
                ('is_active', models.BooleanField(default=True, verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
            ],
        ),
        migrations.CreateModel(
            name='ExtendedKeyUsageExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='FreshestCrlExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameDirectoryName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameDNSName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(editable=False, max_length=1024, unique=True, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameIpAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_type', models.CharField(choices=[('A4', 'IPv4 Address'), ('A6', 'IPv6 Address'), ('N4', 'IPv4 Network'), ('N6', 'IPv6 Network')], editable=False, max_length=2, verbose_name='IP Type')),
                ('value', models.CharField(editable=False, max_length=16384, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameOtherName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type_id', models.CharField(editable=False, max_length=256, verbose_name='OID')),
                ('value', models.CharField(editable=False, max_length=16384, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameRegisteredId',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(editable=False, max_length=256, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameRFC822Name',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(editable=False, max_length=1024, unique=True, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNamesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameUniformResourceIdentifier',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(editable=False, max_length=16384, unique=True, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralSubtree',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('minimum', models.PositiveIntegerField(default=0, editable=False)),
                ('maximum', models.PositiveIntegerField(blank=True, default=None, editable=False, null=True)),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='IDevIDReferenceModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idevid_ref', models.CharField(max_length=255, verbose_name='IDevID Identifier')),
            ],
        ),
        migrations.CreateModel(
            name='InhibitAnyPolicyExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('inhibit_any_policy', models.PositiveIntegerField(blank=True, editable=False, null=True, verbose_name='InhibitAnyPolicy')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='IssuedCredentialModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('common_name', models.CharField(max_length=255, verbose_name='Common Name')),
                ('issued_credential_type', models.IntegerField(choices=[(0, 'Domain Credential'), (1, 'Application Credential')], verbose_name='Credential Type')),
                ('issued_using_cert_profile', models.CharField(default='', max_length=255, verbose_name='Issued using Certificate Profile')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
            ],
        ),
        migrations.CreateModel(
            name='IssuerAlternativeNameExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='KeyPurposeIdModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oid', models.CharField(editable=False, max_length=256, unique=True, verbose_name='Key Purpose OID')),
            ],
        ),
        migrations.CreateModel(
            name='KeyUsageExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('digital_signature', models.BooleanField(default=False, editable=False, verbose_name='Digital Signature')),
                ('content_commitment', models.BooleanField(default=False, editable=False, verbose_name='Content Commitment')),
                ('key_encipherment', models.BooleanField(default=False, editable=False, verbose_name='Key Encipherment')),
                ('data_encipherment', models.BooleanField(default=False, editable=False, verbose_name='Data Encipherment')),
                ('key_agreement', models.BooleanField(default=False, editable=False, verbose_name='Key Agreement')),
                ('key_cert_sign', models.BooleanField(default=False, editable=False, verbose_name='Key Cert Sign')),
                ('crl_sign', models.BooleanField(default=False, editable=False, verbose_name='CRL Sign')),
                ('encipher_only', models.BooleanField(default=False, editable=False, verbose_name='Encipher Only')),
                ('decipher_only', models.BooleanField(default=False, editable=False, verbose_name='Decipher Only')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='NameConstraintsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='NoticeReference',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.CharField(blank=True, editable=False, max_length=200, null=True, verbose_name='Organization')),
                ('notice_numbers', models.CharField(blank=True, editable=False, max_length=1024, null=True, verbose_name='Notice Numbers')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='OwnerCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Unique Name')),
                ('owner_credential_type', models.IntegerField(choices=[(0, 'Local'), (1, 'Remote EST'), (2, 'Remote CMP'), (3, 'Remote EST (Onboarding)')], default=0, help_text='How the DevOwnerID certificate is acquired.', verbose_name='Credential Type')),
                ('remote_host', models.CharField(blank=True, default='', help_text='The hostname or IP address of the remote CA used to enroll this DevOwnerID.', max_length=253, verbose_name='Remote Host')),
                ('remote_port', models.PositiveIntegerField(blank=True, help_text='The port number of the remote CA.', null=True, verbose_name='Remote Port')),
                ('remote_path', models.CharField(blank=True, default='', help_text='The path on the remote CA endpoint (DevOwnerID enrollment).', max_length=255, verbose_name='Remote Path')),
                ('remote_path_domain_credential', models.CharField(blank=True, default='', help_text='The EST path used to obtain the domain credential during onboarding (e.g. /.well-known/est/simpleenroll). Only relevant for EST onboarding.', max_length=255, verbose_name='Remote Path (Domain Credential)')),
                ('est_username', models.CharField(blank=True, default='', help_text='Username for EST authentication when enrolling from a remote CA.', max_length=128, verbose_name='EST Username')),
                ('key_type', models.CharField(blank=True, default='ECC-SECP256R1', help_text='Cryptographic key type used for all DevOwnerID key pairs (e.g. RSA-2048, ECC-SECP256R1).', max_length=32, verbose_name='Key Type')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
            ],
            options={
                'abstract': False,
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='PolicyConstraintsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('require_explicit_policy', models.PositiveIntegerField(blank=True, editable=False, null=True, verbose_name='requireExplicitPolicy')),
                ('inhibit_policy_mapping', models.PositiveIntegerField(blank=True, editable=False, null=True, verbose_name='inhibitPolicyMapping')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='PolicyInformation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy_identifier', models.CharField(editable=False, max_length=256, verbose_name='Policy Identifier')),
            ],
        ),
        migrations.CreateModel(
            name='PolicyMappingModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuer_domain_policy', models.CharField(editable=False, max_length=256, verbose_name='Issuer Domain Policy OID')),
                ('subject_domain_policy', models.CharField(editable=False, max_length=256, verbose_name='Subject Domain Policy OID')),
            ],
        ),
        migrations.CreateModel(
            name='PolicyMappingsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='PolicyQualifierInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('policy_qualifier_id', models.CharField(editable=False, max_length=256, verbose_name='Policy Qualifier ID')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='PrimaryCredentialCertificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_primary', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='QualifierModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='RemoteIssuedCredentialModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('common_name', models.CharField(max_length=255, verbose_name='Common Name')),
                ('issued_credential_type', models.IntegerField(choices=[(0, 'Domain Credential'), (2, 'DevOwnerID'), (3, 'Local CA'), (4, 'RA Device')], verbose_name='Credential Type')),
                ('issued_using_cert_profile', models.CharField(default='', max_length=255, verbose_name='Issued using Certificate Profile')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
            ],
        ),
        migrations.CreateModel(
            name='RevokedCertificateModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('revoked_at', models.DateTimeField(auto_now_add=True, verbose_name='Revocation Date')),
                ('revocation_reason', models.TextField(choices=[('unspecified', 'Unspecified'), ('keyCompromise', 'Key Compromise'), ('cACompromise', 'CA Compromise'), ('affiliationChanged', 'Affiliation Changed'), ('superseded', 'Superseded'), ('cessationOfOperation', 'Cessation of Operation'), ('certificateHold', 'Certificate Hold'), ('privilegeWithdrawn', 'Privilege Withdrawn'), ('aACompromise', 'AA Compromise'), ('removeFromCRL', 'Remove from CRL')], default='unspecified', verbose_name='Revocation Reason')),
            ],
        ),
        migrations.CreateModel(
            name='SubjectAlternativeNameExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='SubjectDirectoryAttributesExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='SubjectInformationAccessExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='SubjectKeyIdentifierExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key_identifier', models.CharField(editable=False, max_length=256, unique=True, verbose_name='Key Identifier')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='TruststoreModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Unique Name')),
                ('intended_usage', models.IntegerField(choices=[(0, 'IDevID'), (1, 'TLS'), (2, 'Generic'), (3, 'Device Owner ID'), (4, 'Issuing CA Chain'), (5, 'OPC UA GDS Push')], verbose_name='Intended Usage')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created-At')),
            ],
        ),
        migrations.CreateModel(
            name='TruststoreOrderModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveSmallIntegerField(editable=False, verbose_name='Trust Store Certificate Index (Order)')),
            ],
        ),
        migrations.CreateModel(
            name='UserNotice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('explicit_text', models.CharField(blank=True, editable=False, max_length=200, null=True, verbose_name='Explicit Text')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='AttributeTypeAndValue',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oid', models.CharField(editable=False, max_length=256, verbose_name='OID')),
                ('value', models.CharField(editable=False, max_length=16384, verbose_name='Value')),
            ],
            options={
                'unique_together': {('oid', 'value')},
            },
        ),
        migrations.CreateModel(
            name='AuthorityInformationAccessExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('authority_info_access_syntax', models.ManyToManyField(blank=True, related_name='authority_info_access_syntax', to='pki.accessdescriptionmodel')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='BasicConstraintsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('ca', models.BooleanField(editable=False, verbose_name='CA')),
                ('path_length_constraint', models.PositiveSmallIntegerField(blank=True, editable=False, null=True, verbose_name='Path Length Constraint')),
            ],
            options={
                'unique_together': {('critical', 'ca', 'path_length_constraint')},
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.CreateModel(
            name='CaModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(help_text='Unique identifier for this CA', max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='CA Name')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this CA is currently active', verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
                ('ca_type', models.IntegerField(blank=True, choices=[(-1, 'Keyless CA'), (0, 'Auto-Generated Root'), (1, 'Auto-Generated'), (2, 'Local-Legacy Software'), (3, 'Local-Managed Backend'), (4, 'Remote-EST-RA'), (5, 'Remote-CMP-RA'), (6, 'Remote-Issuing-EST'), (7, 'Remote-Issuing-CMP')], help_text='Type of CA - KEYLESS for keyless CAs', null=True, verbose_name='CA Type')),
                ('remote_host', models.CharField(blank=True, default='', help_text='The hostname or IP address of the remote PKI', max_length=253, verbose_name='Remote Host')),
                ('remote_port', models.PositiveIntegerField(blank=True, help_text='The port number of the remote PKI', null=True, verbose_name='Remote Port')),
                ('remote_path', models.CharField(blank=True, default='', help_text='The path on the remote PKI', max_length=255, verbose_name='Remote Path')),
                ('est_username', models.CharField(blank=True, default='', help_text='Username for EST authentication', max_length=128, verbose_name='EST Username')),
                ('crl_cycle_enabled', models.BooleanField(default=False, help_text='Enable automatic periodic CRL generation for this CA', verbose_name='Enable CRL Cycle Updates')),
                ('crl_cycle_interval_hours', models.FloatField(default=24.0, help_text='The interval in hours between CRL generations (minimum ~5 minutes)', verbose_name='CRL Cycle Interval (hours)')),
                ('crl_validity_hours', models.FloatField(default=24.0, help_text='The validity period in hours for generated CRLs (nextUpdate field)', verbose_name='CRL Validity (hours)')),
                ('last_crl_generation_started_at', models.DateTimeField(blank=True, help_text='Timestamp when the last CRL generation task was started', null=True, verbose_name='Last CRL Generation Started')),
                ('auto_crl_on_revocation_enabled', models.BooleanField(default=True, help_text='Automatically generate a new CRL when a certificate is revoked', verbose_name='Auto-Generate CRL on Revocation')),
                ('no_onboarding_config', models.ForeignKey(blank=True, help_text='No-onboarding configuration for remote CA connection', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_cas', to='onboarding.noonboardingconfigmodel', verbose_name='No Onboarding Config')),
                ('onboarding_config', models.ForeignKey(blank=True, help_text='Onboarding configuration for remote CA connection', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_cas', to='onboarding.onboardingconfigmodel', verbose_name='Onboarding Config')),
                ('parent_ca', models.ForeignKey(blank=True, help_text='The parent CA in the hierarchy (issuer of this CA)', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='child_cas', to='pki.camodel', verbose_name='Parent CA')),
            ],
            options={
                'verbose_name': 'Certificate Authority',
                'verbose_name_plural': 'Certificate Authorities',
                'db_table': 'pki_genericcamodel',
                'ordering': ['unique_name'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
    ]
