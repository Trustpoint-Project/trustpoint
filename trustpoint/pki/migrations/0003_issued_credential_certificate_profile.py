# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

import django.db.models.deletion
from django.db import migrations, models


PROFILE_MODELS = ('IssuedCredentialModel', 'RemoteIssuedCredentialModel')


def link_existing_profiles(apps, schema_editor):
    profiles = apps.get_model('pki', 'CertificateProfileModel').objects.using(schema_editor.connection.alias)
    for model_name in PROFILE_MODELS:
        issued = apps.get_model('pki', model_name).objects.using(schema_editor.connection.alias)
        if model_name == 'RemoteIssuedCredentialModel':
            # Imports carried a fixed label, not the profile used for issuance.
            issued = issued.exclude(
                issued_credential_type=2,
                owner_credential__owner_credential_type=0,
                issued_using_cert_profile__in=['', 'dev_owner_id'],
            )
        names = (
            issued.exclude(issued_using_cert_profile='').values_list('issued_using_cert_profile', flat=True).distinct()
        )
        for name in names.iterator():
            matches = list(profiles.filter(models.Q(unique_name=name) | models.Q(display_name=name))[:2])
            if len(matches) == 1:
                issued.filter(issued_using_cert_profile=name, certificate_profile__isnull=True).update(
                    certificate_profile_id=matches[0].pk
                )
        unresolved = list(
            issued.filter(certificate_profile__isnull=True).values('pk', 'issued_using_cert_profile')[:20]
        )
        if unresolved:
            raise RuntimeError(
                'Cannot remove saved certificate profile labels. Resolve missing or ambiguous '
                f'issued_using_cert_profile values and profile names for {model_name} before retrying '
                f'the migration (first 20): {unresolved}'
            )


def restore_profile_labels(apps, schema_editor):
    for model_name in PROFILE_MODELS:
        issued = apps.get_model('pki', model_name).objects.using(schema_editor.connection.alias)
        for record in issued.select_related('certificate_profile').iterator():
            profile = record.certificate_profile
            label = (profile.display_name or profile.unique_name) if profile is not None else ''
            issued.filter(pk=record.pk).update(issued_using_cert_profile=label)


class Migration(migrations.Migration):
    dependencies = [
        ('pki', '0002_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='issuedcredentialmodel',
            name='certificate_profile',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='+',
                to='pki.certificateprofilemodel',
            ),
        ),
        migrations.AddField(
            model_name='remoteissuedcredentialmodel',
            name='certificate_profile',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='+',
                to='pki.certificateprofilemodel',
                help_text='Empty for imported DevOwnerID credentials without an issuance profile.',
            ),
        ),
        migrations.RunPython(link_existing_profiles, restore_profile_labels),
        migrations.RemoveField(
            model_name='remoteissuedcredentialmodel',
            name='issued_using_cert_profile',
        ),
        migrations.RemoveField(
            model_name='issuedcredentialmodel',
            name='issued_using_cert_profile',
        ),
        migrations.AlterField(
            model_name='issuedcredentialmodel',
            name='certificate_profile',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT, related_name='+', to='pki.certificateprofilemodel'
            ),
        ),
    ]
