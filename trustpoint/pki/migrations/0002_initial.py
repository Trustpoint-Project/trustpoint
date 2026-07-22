import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('crypto', '0001_initial'),
        ('devices', '0002_initial'),
        ('onboarding', '0002_initial'),
        ('pki', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='carollovermodel',
            name='initiated_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL, verbose_name='Initiated By'),
        ),
        migrations.AddField(
            model_name='carollovermodel',
            name='new_issuing_ca',
            field=models.ForeignKey(blank=True, help_text='The replacement Issuing CA. Null until the new CA is ready.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_new', to='pki.camodel', verbose_name='New Issuing CA'),
        ),
        migrations.AddField(
            model_name='carollovermodel',
            name='old_issuing_ca',
            field=models.ForeignKey(help_text='The Issuing CA being replaced.', on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_old', to='pki.camodel', verbose_name='Old Issuing CA'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='authority_information_access_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.authorityinformationaccessextension'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='authority_key_identifier_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.authoritykeyidentifierextension', verbose_name='Authority Key Identifier'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='basic_constraints_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.basicconstraintsextension', verbose_name='Basic Constraints'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='issuer',
            field=models.ManyToManyField(editable=False, related_name='issuer', to='pki.attributetypeandvalue', verbose_name='Issuer'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='issuer_id',
            field=models.ForeignKey(blank=True, db_column='issuer_id', null=True, on_delete=django.db.models.deletion.SET_NULL, to='pki.certificatemodel', verbose_name='Issuer Certificate'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject',
            field=models.ManyToManyField(editable=False, related_name='subject', to='pki.attributetypeandvalue', verbose_name='Subject'),
        ),
        migrations.AddField(
            model_name='certificatechainordermodel',
            name='certificate',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='certificatechainordermodel',
            name='primary_certificate',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.PROTECT, related_name='primary_certificate_set', to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='camodel',
            name='certificate',
            field=models.ForeignKey(blank=True, help_text='The CA certificate (for keyless CAs)', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='keyless_cas', to='pki.certificatemodel', verbose_name='CA Certificate'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='certificate_policies_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.certificatepoliciesextension', verbose_name='Certificate Policies'),
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='certificate',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='credential_set', to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='certificate_chain',
            field=models.ManyToManyField(blank=True, related_name='credential_certificate_chains', through='pki.CertificateChainOrderModel', through_fields=('credential', 'certificate'), to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='managed_private_key',
            field=models.ForeignKey(blank=True, help_text='Reference to the configured Trustpoint crypto backend managed key', null=True, on_delete=django.db.models.deletion.PROTECT, to='crypto.cryptomanagedkeymodel', verbose_name='Managed Private Key'),
        ),
        migrations.AddField(
            model_name='certificatechainordermodel',
            name='credential',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel'),
        ),
        migrations.AddField(
            model_name='camodel',
            name='credential',
            field=models.OneToOneField(blank=True, help_text='The CA credential with private key (for issuing CAs)', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='issuing_ca', to='pki.credentialmodel', verbose_name='Credential'),
        ),
        migrations.AddField(
            model_name='activetrustpointtlsservercredentialmodel',
            name='credential',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='crl_distribution_points_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.crldistributionpointsextension'),
        ),
        migrations.AddField(
            model_name='crlmodel',
            name='ca',
            field=models.ForeignKey(blank=True, help_text='The CA that issued this CRL', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='crls', to='pki.camodel', verbose_name='Certificate Authority'),
        ),
        migrations.AddField(
            model_name='crldistributionpointsextension',
            name='distribution_points',
            field=models.ManyToManyField(blank=True, to='pki.distributionpointmodel', verbose_name='Distribution Points'),
        ),
        migrations.AddField(
            model_name='distributionpointname',
            name='name_relative_to_crl_issuer',
            field=models.ManyToManyField(blank=True, editable=False, related_name='distribution_point_name', to='pki.attributetypeandvalue', verbose_name='Name relative to crl issuer'),
        ),
        migrations.AddField(
            model_name='distributionpointmodel',
            name='distribution_point_name',
            field=models.ForeignKey(blank=True, on_delete=django.db.models.deletion.PROTECT, to='pki.distributionpointname', verbose_name='Distribution Point Name'),
        ),
        migrations.AddField(
            model_name='domainallowedcertificateprofilemodel',
            name='certificate_profile',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='domains', to='pki.certificateprofilemodel'),
        ),
        migrations.AddField(
            model_name='domainmodel',
            name='domain_credential_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used for issuing domain credentials. Defaults to "domain_credential".', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='domains_as_credential_profile', to='pki.certificateprofilemodel', verbose_name='Domain Credential Profile'),
        ),
        migrations.AddField(
            model_name='domainmodel',
            name='issuing_ca',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='domains', to='pki.camodel', verbose_name='Issuing CA'),
        ),
        migrations.AddField(
            model_name='domainallowedcertificateprofilemodel',
            name='domain',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='certificate_profiles', to='pki.domainmodel'),
        ),
        migrations.AddField(
            model_name='devidregistration',
            name='domain',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='devid_registrations', to='pki.domainmodel', verbose_name='Associated Domain'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='extended_key_usage_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.extendedkeyusageextension', verbose_name='Extended Key Usage'),
        ),
        migrations.AddField(
            model_name='freshestcrlextension',
            name='distribution_points',
            field=models.ManyToManyField(blank=True, to='pki.distributionpointmodel'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='freshest_crl_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.freshestcrlextension'),
        ),
        migrations.AddField(
            model_name='generalnamedirectoryname',
            name='names',
            field=models.ManyToManyField(editable=False, to='pki.attributetypeandvalue', verbose_name='Name'),
        ),
        migrations.AlterUniqueTogether(
            name='generalnameipaddress',
            unique_together={('ip_type', 'value')},
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='directory_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamedirectoryname'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='dns_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamednsname'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='ip_address',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameipaddress'),
        ),
        migrations.AddField(
            model_name='accessdescriptionmodel',
            name='access_location',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamemodel', verbose_name='Access Location'),
        ),
        migrations.AlterUniqueTogether(
            name='generalnameothername',
            unique_together={('type_id', 'value')},
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
        migrations.AddField(
            model_name='generalnamesmodel',
            name='directory_names',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnamedirectoryname', verbose_name='Directory Names'),
        ),
        migrations.AddField(
            model_name='generalnamesmodel',
            name='dns_names',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnamednsname', verbose_name='DNS Names'),
        ),
        migrations.AddField(
            model_name='generalnamesmodel',
            name='ip_addresses',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnameipaddress', verbose_name='IP Addresses'),
        ),
        migrations.AddField(
            model_name='generalnamesmodel',
            name='other_names',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnameothername', verbose_name='Other Names'),
        ),
        migrations.AddField(
            model_name='generalnamesmodel',
            name='registered_ids',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnameregisteredid', verbose_name='Registered IDs'),
        ),
        migrations.AddField(
            model_name='generalnamesmodel',
            name='rfc822_names',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnamerfc822name', verbose_name='RFC822 Names'),
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
            model_name='generalnamesmodel',
            name='uniform_resource_identifiers',
            field=models.ManyToManyField(related_name='general_names_set', to='pki.generalnameuniformresourceidentifier', verbose_name='Uniform Resource Identifiers'),
        ),
        migrations.AddField(
            model_name='generalnamemodel',
            name='uri',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnameuniformresourceidentifier'),
        ),
        migrations.AddField(
            model_name='generalsubtree',
            name='base',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamemodel'),
        ),
        migrations.AddField(
            model_name='idevidreferencemodel',
            name='dev_owner_id_certificate',
            field=models.ForeignKey(blank=True, help_text='The DevOwnerID certificate whose SAN contained this IDevID reference.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='idevid_refs', to='pki.certificatemodel', verbose_name='DevOwnerID Certificate'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='inhibit_any_policy_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.inhibitanypolicyextension'),
        ),
        migrations.AddField(
            model_name='issuedcredentialmodel',
            name='credential',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='issued_credential', to='pki.credentialmodel', verbose_name='Credential'),
        ),
        migrations.AddField(
            model_name='issuedcredentialmodel',
            name='device',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='issued_credentials', to='devices.devicemodel', verbose_name='Device'),
        ),
        migrations.AddField(
            model_name='issuedcredentialmodel',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='issued_credentials', to='pki.domainmodel', verbose_name='Domain'),
        ),
        migrations.AddField(
            model_name='issueralternativenameextension',
            name='issuer_alt_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='Issuer Alternative Name Issuer'),
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
        migrations.AlterUniqueTogether(
            name='keyusageextension',
            unique_together={('digital_signature', 'content_commitment', 'key_encipherment', 'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign', 'encipher_only', 'decipher_only')},
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='key_usage_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.keyusageextension', verbose_name='Key Usage'),
        ),
        migrations.AddField(
            model_name='nameconstraintsextension',
            name='excluded_subtrees',
            field=models.ManyToManyField(editable=False, related_name='excluded_subtrees_set', to='pki.generalsubtree'),
        ),
        migrations.AddField(
            model_name='nameconstraintsextension',
            name='permitted_subtrees',
            field=models.ManyToManyField(editable=False, related_name='permitted_subtrees_set', to='pki.generalsubtree'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='name_constraints_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.nameconstraintsextension'),
        ),
        migrations.AddField(
            model_name='ownercredentialmodel',
            name='no_onboarding_config',
            field=models.ForeignKey(blank=True, help_text='No-onboarding configuration (manual or EST username/password).', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='owner_credentials', to='onboarding.noonboardingconfigmodel', verbose_name='No Onboarding Config'),
        ),
        migrations.AddField(
            model_name='ownercredentialmodel',
            name='onboarding_config',
            field=models.ForeignKey(blank=True, help_text='Onboarding configuration used for remote CA enrollment.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='owner_credentials', to='onboarding.onboardingconfigmodel', verbose_name='Onboarding Config'),
        ),
        migrations.AddField(
            model_name='idevidreferencemodel',
            name='dev_owner_id',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='idevid_ref_set', to='pki.ownercredentialmodel'),
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
        migrations.AlterUniqueTogether(
            name='policymappingmodel',
            unique_together={('issuer_domain_policy', 'subject_domain_policy')},
        ),
        migrations.AddField(
            model_name='policymappingsextension',
            name='policy_mappings',
            field=models.ManyToManyField(editable=False, related_name='policy_mappings_extension', to='pki.policymappingmodel'),
        ),
        migrations.AddField(
            model_name='policyinformation',
            name='policy_qualifiers',
            field=models.ManyToManyField(blank=True, editable=False, related_name='policies', to='pki.policyqualifierinfo'),
        ),
        migrations.AddField(
            model_name='primarycredentialcertificate',
            name='certificate',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='primarycredentialcertificate',
            name='credential',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='pki.credentialmodel'),
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='certificates',
            field=models.ManyToManyField(blank=True, related_name='credential', through='pki.PrimaryCredentialCertificate', to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='qualifiermodel',
            name='cps_uri',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='qualifiers', to='pki.cpsurimodel'),
        ),
        migrations.AddField(
            model_name='policyqualifierinfo',
            name='qualifier',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.qualifiermodel'),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='ca',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.camodel', verbose_name='CA'),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='credential',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='remote_issued_credential', to='pki.credentialmodel', verbose_name='Credential'),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='device',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='devices.devicemodel', verbose_name='Device'),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='domain',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.domainmodel', verbose_name='Domain'),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='owner_credential',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='remote_issued_credentials', to='pki.ownercredentialmodel', verbose_name='Owner Credential'),
        ),
        migrations.AddField(
            model_name='revokedcertificatemodel',
            name='ca',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revoked_certificates', to='pki.camodel', verbose_name='Issuing CA'),
        ),
        migrations.AddField(
            model_name='revokedcertificatemodel',
            name='certificate',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='revoked_certificate', to='pki.certificatemodel', verbose_name='Certificate'),
        ),
        migrations.AddField(
            model_name='subjectalternativenameextension',
            name='subject_alt_name',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.generalnamesmodel', verbose_name='Subject Alternative Name Subject'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_alternative_name_extension',
            field=models.ForeignKey(blank=True, editable=False, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='certificates', to='pki.subjectalternativenameextension', verbose_name='Subject Alternative Name'),
        ),
        migrations.AddField(
            model_name='subjectdirectoryattributesextension',
            name='subject_directory_attributes',
            field=models.ManyToManyField(blank=True, editable=False, to='pki.attributetypeandvalue', verbose_name='Subject Directory Attributes'),
        ),
        migrations.AddField(
            model_name='certificatemodel',
            name='subject_directory_attributes_extension',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.subjectdirectoryattributesextension'),
        ),
        migrations.AddField(
            model_name='subjectinformationaccessextension',
            name='subject_info_access_syntax',
            field=models.ManyToManyField(blank=True, related_name='subject_info_access_syntax', to='pki.accessdescriptionmodel'),
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
        migrations.AddField(
            model_name='devidregistration',
            name='truststore',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='devid_registrations', to='pki.truststoremodel', verbose_name='Associated Truststore'),
        ),
        migrations.AddField(
            model_name='camodel',
            name='chain_truststore',
            field=models.OneToOneField(blank=True, help_text='The truststore containing the full certificate chain for this CA.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='issuing_ca', to='pki.truststoremodel', verbose_name='Chain Truststore'),
        ),
        migrations.AddField(
            model_name='truststoreordermodel',
            name='certificate',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='trust_store_components', to='pki.certificatemodel'),
        ),
        migrations.AddField(
            model_name='truststoreordermodel',
            name='trust_store',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to='pki.truststoremodel'),
        ),
        migrations.AddField(
            model_name='truststoremodel',
            name='certificates',
            field=models.ManyToManyField(through='pki.TruststoreOrderModel', to='pki.certificatemodel', verbose_name='Truststore certificates'),
        ),
        migrations.AddField(
            model_name='usernotice',
            name='notice_ref',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to='pki.noticereference'),
        ),
        migrations.AddField(
            model_name='qualifiermodel',
            name='user_notice',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='qualifiers', to='pki.usernotice'),
        ),
        migrations.AddConstraint(
            model_name='carollovermodel',
            constraint=models.UniqueConstraint(condition=models.Q(('state__in', ['planned', 'awaiting_new_ca', 'preparation', 'transition'])), fields=('old_issuing_ca',), name='unique_active_rollover_per_old_ca'),
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
        migrations.AddIndex(
            model_name='revokedcertificatemodel',
            index=models.Index(fields=['ca', 'revoked_at'], name='pki_revoked_ca_revoked_at_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_after'], name='pki_cert_not_valid_after_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_before'], name='pki_cert_not_valid_before_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['serial_number'], name='pki_cert_serial_num_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['subject_public_bytes'], name='pki_cert_subj_pub_bytes_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['issuer_public_bytes', 'issuer_id'], name='pki_cert_iss_pub_bytes_idx'),
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
