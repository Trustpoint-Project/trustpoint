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
        ('devices', '0001_initial'),
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
            name='CrlDistributionPointsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
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
            name='ExtendedKeyUsageExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
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
            name='GeneralNameUniformResourceIdentifier',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(editable=False, max_length=16384, unique=True, verbose_name='Value')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
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
            name='KeyPurposeIdModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('oid', models.CharField(editable=False, max_length=256, unique=True, verbose_name='Key Purpose OID')),
            ],
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
                ('authority_information_access_extension', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.authorityinformationaccessextension')),
                ('authority_key_identifier_extension', models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.authoritykeyidentifierextension', verbose_name='Authority Key Identifier')),
                ('basic_constraints_extension', models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.basicconstraintsextension', verbose_name='Basic Constraints')),
                ('issuer', models.ManyToManyField(editable=False, related_name='issuer', to='pki.attributetypeandvalue', verbose_name='Issuer')),
                ('issuer_id', models.ForeignKey(blank=True, db_column='issuer_id', null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki.certificatemodel', verbose_name='Issuer Certificate')),
                ('subject', models.ManyToManyField(editable=False, related_name='subject', to='pki.attributetypeandvalue', verbose_name='Subject')),
                ('certificate_policies_extension', models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.certificatepoliciesextension', verbose_name='Certificate Policies')),
                ('crl_distribution_points_extension', models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.crldistributionpointsextension')),
                ('extended_key_usage_extension', models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.extendedkeyusageextension', verbose_name='Extended Key Usage')),
            ],
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='CertificateChainOrderModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveIntegerField(editable=False)),
                ('certificate', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, to='pki.certificatemodel')),
                ('primary_certificate', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='primary_certificate_set', to='pki.certificatemodel')),
            ],
            options={
                'ordering': ['order'],
            },
        ),
        migrations.CreateModel(
            name='CredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('credential_type', models.IntegerField(choices=[(0, 'Trustpoint TLS Server'), (1, 'Root CA'), (2, 'Issuing CA'), (3, 'Issued Credential'), (4, 'DevOwnerID'), (5, 'Signer')], verbose_name='Credential Type')),
                ('private_key', util.encrypted_fields.EncryptedCharField(blank=True, default='', max_length=9500, verbose_name='Private key (PEM)')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('certificate', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='credential_set', to='pki.certificatemodel')),
                ('certificate_chain', models.ManyToManyField(blank=True, related_name='credential_certificate_chains', through='pki.CertificateChainOrderModel', through_fields=('credential', 'certificate'), to='pki.certificatemodel')),
            ],
            options={
                'abstract': False,
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.AddField(
            model_name='certificatechainordermodel',
            name='credential',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel'),
        ),
        migrations.CreateModel(
            name='CaModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(help_text='Unique identifier for this CA', max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='CA Name')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this CA is currently active', verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
                ('ca_type', models.IntegerField(blank=True, choices=[(-1, 'Keyless CA'), (0, 'Auto-Generated Root'), (1, 'Auto-Generated'), (2, 'Local-Unprotected'), (3, 'Local-PKCS11'), (4, 'Remote-EST-RA'), (5, 'Remote-CMP-RA'), (6, 'Remote-Issuing-EST'), (7, 'Remote-Issuing-CMP')], help_text='Type of CA - KEYLESS for keyless CAs', null=True, verbose_name='CA Type')),
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
                ('certificate', models.ForeignKey(blank=True, help_text='The CA certificate (for keyless CAs)', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='keyless_cas', to='pki.certificatemodel', verbose_name='CA Certificate')),
                ('credential', models.OneToOneField(blank=True, help_text='The CA credential with private key (for issuing CAs)', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='issuing_ca', to='pki.credentialmodel', verbose_name='Credential')),
                ('chain_truststore', models.OneToOneField(blank=True, help_text='The truststore containing the full certificate chain for this CA.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='issuing_ca', to='pki.truststoremodel', verbose_name='Chain Truststore')),
            ],
            options={
                'verbose_name': 'Certificate Authority',
                'verbose_name_plural': 'Certificate Authorities',
                'db_table': 'pki_genericcamodel',
                'ordering': ['unique_name'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='ActiveTrustpointTlsServerCredentialModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('credential', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel')),
            ],
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
                ('ca', models.ForeignKey(blank=True, help_text='The CA that issued this CRL', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='crls', to='pki.camodel', verbose_name='Certificate Authority')),
            ],
            options={
                'verbose_name': 'Certificate Revocation List',
                'verbose_name_plural': 'Certificate Revocation Lists',
                'ordering': ['-this_update'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.AddField(
            model_name='crldistributionpointsextension',
            name='distribution_points',
            field=models.ManyToManyField(blank=True, to='pki.distributionpointmodel', verbose_name='Distribution Points'),
        ),
        migrations.CreateModel(
            name='DistributionPointName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name_relative_to_crl_issuer', models.ManyToManyField(blank=True, editable=False, related_name='distribution_point_name', to='pki.attributetypeandvalue', verbose_name='Name relative to crl issuer')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='distributionpointmodel',
            name='distribution_point_name',
            field=models.ForeignKey(blank=True, on_delete=django.db.models.deletion.PROTECT, to='pki.distributionpointname', verbose_name='Distribution Point Name'),
        ),
        migrations.CreateModel(
            name='DomainModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Domain Name')),
                ('is_active', models.BooleanField(default=True, verbose_name='Active')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated')),
                ('issuing_ca', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='domains', to='pki.camodel', verbose_name='Issuing CA')),
            ],
        ),
        migrations.CreateModel(
            name='DomainAllowedCertificateProfileModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alias', models.CharField(default='', max_length=255)),
                ('certificate_profile', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='domains', to='pki.certificateprofilemodel')),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='certificate_profiles', to='pki.domainmodel')),
            ],
        ),
        migrations.CreateModel(
            name='FreshestCrlExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('distribution_points', models.ManyToManyField(blank=True, to='pki.distributionpointmodel')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='freshest_crl_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.freshestcrlextension'),
        ),
        migrations.CreateModel(
            name='GeneralNameDirectoryName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('names', models.ManyToManyField(editable=False, to='pki.attributetypeandvalue', verbose_name='Name')),
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
            options={
                'unique_together': {('ip_type', 'value')},
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.CreateModel(
            name='GeneralNameModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('directory_name', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamedirectoryname')),
                ('dns_name', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamednsname')),
                ('ip_address', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameipaddress')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='accessdescriptionmodel',
            name='access_location',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamemodel', verbose_name='Access Location'),
        ),
        migrations.CreateModel(
            name='GeneralNameOtherName',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type_id', models.CharField(editable=False, max_length=256, verbose_name='OID')),
                ('value', models.CharField(editable=False, max_length=16384, verbose_name='Value')),
            ],
            options={
                'unique_together': {('type_id', 'value')},
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='other_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameothername'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='registered_id',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameregisteredid'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='rfc822_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamerfc822name'),
        ),
        migrations.CreateModel(
            name='GeneralNamesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('directory_names', models.ManyToManyField(related_name='general_names_set', to='pki.generalnamedirectoryname', verbose_name='Directory Names')),
                ('dns_names', models.ManyToManyField(related_name='general_names_set', to='pki.generalnamednsname', verbose_name='DNS Names')),
                ('ip_addresses', models.ManyToManyField(related_name='general_names_set', to='pki.generalnameipaddress', verbose_name='IP Addresses')),
                ('other_names', models.ManyToManyField(related_name='general_names_set', to='pki.generalnameothername', verbose_name='Other Names')),
                ('registered_ids', models.ManyToManyField(related_name='general_names_set', to='pki.generalnameregisteredid', verbose_name='Registered IDs')),
                ('rfc822_names', models.ManyToManyField(related_name='general_names_set', to='pki.generalnamerfc822name', verbose_name='RFC822 Names')),
                ('uniform_resource_identifiers', models.ManyToManyField(related_name='general_names_set', to='pki.generalnameuniformresourceidentifier', verbose_name='Uniform Resource Identifiers')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='distributionpointname',
            name='full_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel'),
        ),
        migrations.AddField(
            model_name='distributionpointmodel',
            name='crl_issuer',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='CRL Issuer'),
        ),
        migrations.AddField(
            model_name='authoritykeyidentifierextension',
            name='authority_cert_issuer',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='Issuer Alternative Name Issuer'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='uri',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameuniformresourceidentifier'),
        ),
        migrations.CreateModel(
            name='GeneralSubtree',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('minimum', models.PositiveIntegerField(default=0, editable=False)),
                ('maximum', models.PositiveIntegerField(blank=True, default=None, editable=False, null=True)),
                ('base', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamemodel')),
            ],
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='inhibit_any_policy_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.inhibitanypolicyextension'),
        ),
        migrations.CreateModel(
            name='IssuedCredentialModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('common_name', models.CharField(max_length=255, verbose_name='Common Name')),
                ('issued_credential_type', models.IntegerField(choices=[(0, 'Domain Credential'), (1, 'Application Credential')], verbose_name='Credential Type')),
                ('issued_using_cert_profile', models.CharField(default='', max_length=255, verbose_name='Issued using Certificate Profile')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('credential', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='issued_credential', to='pki.credentialmodel', verbose_name='Credential')),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='issued_credentials', to='devices.devicemodel', verbose_name='Device')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='issued_credentials', to='pki.domainmodel', verbose_name='Domain')),
            ],
        ),
        migrations.CreateModel(
            name='IssuerAlternativeNameExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('issuer_alt_name', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='Issuer Alternative Name Issuer')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='issuer_alternative_name_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.issueralternativenameextension', verbose_name='Issuer Alternative Name'),
        ),
        migrations.AddField(
            model_name='extendedkeyusageextension',
            name='key_purpose_ids',
            field=models.ManyToManyField(editable=False, related_name='extended_key_usages', to='pki.keypurposeidmodel'),
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
            options={
                'unique_together': {('digital_signature', 'content_commitment', 'key_encipherment', 'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only')},
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='key_usage_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.keyusageextension', verbose_name='Key Usage'),
        ),
        migrations.CreateModel(
            name='NameConstraintsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('excluded_subtrees', models.ManyToManyField(editable=False, related_name='excluded_subtrees_set', to='pki.generalsubtree')),
                ('permitted_subtrees', models.ManyToManyField(editable=False, related_name='permitted_subtrees_set', to='pki.generalsubtree')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='name_constraints_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.nameconstraintsextension'),
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
                ('no_onboarding_config', models.ForeignKey(blank=True, help_text='No-onboarding configuration (manual or EST username/password).', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='owner_credentials', to='onboarding.noonboardingconfigmodel', verbose_name='No Onboarding Config')),
                ('onboarding_config', models.ForeignKey(blank=True, help_text='Onboarding configuration used for remote CA enrollment.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='owner_credentials', to='onboarding.onboardingconfigmodel', verbose_name='Onboarding Config')),
            ],
            options={
                'abstract': False,
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.CreateModel(
            name='IDevIDReferenceModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idevid_ref', models.CharField(max_length=255, verbose_name='IDevID Identifier')),
                ('dev_owner_id_certificate', models.ForeignKey(blank=True, help_text='The DevOwnerID certificate whose SAN contained this IDevID reference.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='idevid_refs', to='pki.certificatemodel', verbose_name='DevOwnerID Certificate')),
                ('dev_owner_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='idevid_ref_set', to='pki.ownercredentialmodel')),
            ],
        ),
        migrations.CreateModel(
            name='PKCS11Key',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token_label', models.CharField(help_text='Label of the HSM token containing the private key', max_length=255, verbose_name='Token Label')),
                ('key_label', models.CharField(help_text='Unique label of the private key within the token', max_length=255, verbose_name='Key Label')),
                ('key_type', models.CharField(choices=[('rsa', 'RSA'), ('ec', 'Elliptic Curve'), ('aes', 'AES')], help_text='Type of the cryptographic key (RSA or EC)', max_length=10, verbose_name='Key Type')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'PKCS#11 Private Key',
                'verbose_name_plural': 'PKCS#11 Private Keys',
                'unique_together': {('token_label', 'key_label')},
            },
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='pkcs11_private_key',
            field=models.ForeignKey(blank=True, help_text='Reference to HSM-stored private key', null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.pkcs11key', verbose_name='PKCS#11 Private Key'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='policy_constraints_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.policyconstraintsextension'),
        ),
        migrations.AddField(
            model_name='certificatepoliciesextension',
            name='certificate_policies',
            field=models.ManyToManyField(editable=False, related_name='certificate_policies', to='pki.policyinformation'),
        ),
        migrations.CreateModel(
            name='PolicyMappingModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuer_domain_policy', models.CharField(editable=False, max_length=256, verbose_name='Issuer Domain Policy OID')),
                ('subject_domain_policy', models.CharField(editable=False, max_length=256, verbose_name='Subject Domain Policy OID')),
            ],
            options={
                'unique_together': {('issuer_domain_policy', 'subject_domain_policy')},
            },
        ),
        migrations.CreateModel(
            name='PolicyMappingsExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('policy_mappings', models.ManyToManyField(editable=False, related_name='policy_mappings_extension', to='pki.policymappingmodel')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='policyinformation',
            name='policy_qualifiers',
            field=models.ManyToManyField(blank=True, editable=False, related_name='policies', to='pki.policyqualifierinfo'),
        ),
        migrations.CreateModel(
            name='PrimaryCredentialCertificate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_primary', models.BooleanField(default=False)),
                ('certificate', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='pki.certificatemodel')),
                ('credential', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel')),
            ],
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='certificates',
            field=models.ManyToManyField(blank=True, related_name='credential', through='pki.PrimaryCredentialCertificate', to='pki.certificatemodel'),
        ),
        migrations.CreateModel(
            name='QualifierModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cps_uri', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='qualifiers', to='pki.cpsurimodel')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='policyqualifierinfo',
            name='qualifier',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.qualifiermodel'),
        ),
        migrations.CreateModel(
            name='RemoteIssuedCredentialModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('common_name', models.CharField(max_length=255, verbose_name='Common Name')),
                ('issued_credential_type', models.IntegerField(choices=[(0, 'Domain Credential'), (2, 'DevOwnerID'), (3, 'Local CA'), (4, 'RA Device')], verbose_name='Credential Type')),
                ('issued_using_cert_profile', models.CharField(default='', max_length=255, verbose_name='Issued using Certificate Profile')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='Created')),
                ('ca', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.camodel', verbose_name='CA')),
                ('credential', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='remote_issued_credential', to='pki.credentialmodel', verbose_name='Credential')),
                ('device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='devices.devicemodel', verbose_name='Device')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.domainmodel', verbose_name='Domain')),
                ('owner_credential', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.ownercredentialmodel', verbose_name='Owner Credential')),
            ],
        ),
        migrations.CreateModel(
            name='RevokedCertificateModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('revoked_at', models.DateTimeField(auto_now_add=True, verbose_name='Revocation Date')),
                ('revocation_reason', models.TextField(choices=[('unspecified', 'Unspecified'), ('keyCompromise', 'Key Compromise'), ('cACompromise', 'CA Compromise'), ('affiliationChanged', 'Affiliation Changed'), ('superseded', 'Superseded'), ('cessationOfOperation', 'Cessation of Operation'), ('certificateHold', 'Certificate Hold'), ('privilegeWithdrawn', 'Privilege Withdrawn'), ('aACompromise', 'AA Compromise'), ('removeFromCRL', 'Remove from CRL')], default='unspecified', verbose_name='Revocation Reason')),
                ('ca', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revoked_certificates', to='pki.camodel', verbose_name='Issuing CA')),
                ('certificate', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='revoked_certificate', to='pki.certificatemodel', verbose_name='Certificate')),
            ],
        ),
        migrations.CreateModel(
            name='SubjectAlternativeNameExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('subject_alt_name', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='Subject Alternative Name Subject')),
            ],
            options={
                'abstract': False,
            },
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_alternative_name_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.subjectalternativenameextension', verbose_name='Subject Alternative Name'),
        ),
        migrations.CreateModel(
            name='SubjectDirectoryAttributesExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('subject_directory_attributes', models.ManyToManyField(blank=True, editable=False, to='pki.attributetypeandvalue', verbose_name='Subject Directory Attributes')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_directory_attributes_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.subjectdirectoryattributesextension'),
        ),
        migrations.CreateModel(
            name='SubjectInformationAccessExtension',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('critical', models.BooleanField(editable=False, verbose_name='Critical')),
                ('subject_info_access_syntax', models.ManyToManyField(blank=True, related_name='subject_info_access_syntax', to='pki.accessdescriptionmodel')),
            ],
            bases=(pki.models.extension.CertificateExtension, models.Model),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_information_access_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.subjectinformationaccessextension'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_key_identifier_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.subjectkeyidentifierextension', verbose_name='Subject Key Identifier'),
        ),
        migrations.CreateModel(
            name='DevIdRegistration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_name', models.CharField(max_length=100, unique=True, validators=[util.field.UniqueNameValidator()], verbose_name='Unique Name')),
                ('serial_number_pattern', models.CharField(help_text='A regex pattern to match valid serial numbers for this registration.', max_length=255, verbose_name='Serial Number Pattern')),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='devid_registrations', to='pki.domainmodel', verbose_name='Associated Domain')),
                ('truststore', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='devid_registrations', to='pki.truststoremodel', verbose_name='Associated Truststore')),
            ],
        ),
        migrations.CreateModel(
            name='TruststoreOrderModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order', models.PositiveSmallIntegerField(editable=False, verbose_name='Trust Store Certificate Index (Order)')),
                ('certificate', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='trust_store_components', to='pki.certificatemodel')),
                ('trust_store', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to='pki.truststoremodel')),
            ],
        ),
        migrations.AddField(
            model_name='truststoremodel',
            name='certificates',
            field=models.ManyToManyField(through='pki.TruststoreOrderModel', to='pki.certificatemodel', verbose_name='Truststore certificates'),
        ),
        migrations.CreateModel(
            name='UserNotice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('explicit_text', models.CharField(blank=True, editable=False, max_length=200, null=True, verbose_name='Explicit Text')),
                ('notice_ref', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.noticereference')),
            ],
            options={
                'abstract': False,
            },
            bases=(util.db.OrphanDeletionMixin, models.Model),
        ),
        migrations.AddField(
            model_name='qualifiermodel',
            name='user_notice',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='qualifiers', to='pki.usernotice'),
        ),
        migrations.AddConstraint(
            model_name='certificatechainordermodel',
            constraint=models.UniqueConstraint(fields=('credential', 'primary_certificate', 'order'), name='unique_group_order'),
        ),
        migrations.AddIndex(
            model_name='crlmodel',
            index=models.Index(fields=['ca', '-this_update'], name='pki_crlmode_ca_id_ba124c_idx'),
        ),
        migrations.AddIndex(
            model_name='crlmodel',
            index=models.Index(fields=['ca', 'is_active'], name='pki_crlmode_ca_id_e556ea_idx'),
        ),
        migrations.AlterUniqueTogether(
            name='crlmodel',
            unique_together={('ca', 'crl_number')},
        ),
        migrations.AddConstraint(
            model_name='domainallowedcertificateprofilemodel',
            constraint=models.UniqueConstraint(condition=models.Q(('alias', ''), _negated=True), fields=('domain', 'alias'), name='unique_domain_alias_when_not_empty'),
        ),
        migrations.AddConstraint(
            model_name='domainallowedcertificateprofilemodel',
            constraint=models.UniqueConstraint(fields=('domain', 'certificate_profile'), name='unique_domain_certificate_profile'),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('ca_type', -1), ('certificate__isnull', False), ('credential__isnull', True)), models.Q(('ca_type__in', [4, 5]), ('credential__isnull', True)), models.Q(('ca_type__in', [0, 1, 2, 3, 6, 7]), ('certificate__isnull', True), ('credential__isnull', False)), _connector='OR'), name='ca_mode_constraint', violation_error_message='Invalid CA configuration'),
        ),
        migrations.AlterUniqueTogether(
            name='truststoreordermodel',
            unique_together={('order', 'trust_store')},
        ),
    ]