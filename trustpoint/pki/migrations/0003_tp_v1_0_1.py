# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Upgrade the PKI schema and existing data from Trustpoint 1.0.0 to 1.0.1."""

from typing import Any, ClassVar

import django.db.models.deletion
from cryptography import x509
from django.db import migrations, models

PROFILE_MODELS = ('IssuedCredentialModel', 'RemoteIssuedCredentialModel')


def link_existing_profiles(apps: Any, schema_editor: Any) -> None:
    """Resolve saved profile labels before removing the legacy fields."""
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
            message = (
                'Cannot remove saved certificate profile labels. Resolve missing or ambiguous '
                f'issued_using_cert_profile values and profile names for {model_name} before retrying '
                f'the migration (first 20): {unresolved}'
            )
            raise RuntimeError(message)
    # Drain deferred foreign-key checks before altering the issued credential tables on PostgreSQL.
    schema_editor.connection.check_constraints()


def restore_profile_labels(apps: Any, schema_editor: Any) -> None:
    """Restore profile labels when reversing the migration."""
    for model_name in PROFILE_MODELS:
        issued = apps.get_model('pki', model_name).objects.using(schema_editor.connection.alias)
        for record in issued.select_related('certificate_profile').iterator():
            profile = record.certificate_profile
            label = (profile.display_name or profile.unique_name) if profile is not None else ''
            issued.filter(pk=record.pk).update(issued_using_cert_profile=label)
    schema_editor.connection.check_constraints()


MANAGEMENT_CA_NAMES = ('Management Root CA', 'Management Issuing CA')
MANAGEMENT_CAPABLE_TYPES = [2, 3, 4, 5, 6, 7, 8]


def mark_builtin_management_cas(apps: Any, _schema_editor: Any) -> None:
    """Keep existing generated management CAs usable after adding the role field."""
    ca_model = apps.get_model('pki', 'CaModel')
    ca_model.objects.filter(
        unique_name__in=MANAGEMENT_CA_NAMES,
        ca_type__in=MANAGEMENT_CAPABLE_TYPES,
    ).update(ca_role=1)


def fold_owner_credentials(apps: Any, schema_editor: Any) -> None:  # noqa: C901
    """Move the IDevID references onto the credential rows.

    shortcut: rollback cannot restore the owner grouping, upgrade only (branch is unreleased).
    """
    remote = apps.get_model('pki', 'RemoteIssuedCredentialModel')
    reference = apps.get_model('pki', 'IDevIDReferenceModel')

    renewed_refs = []
    for ref in reference.objects.all().iterator():
        owner_id = ref.dev_owner_id_id
        candidates = remote.objects.filter(owner_credential_id=owner_id, issued_credential_type=2).order_by(
            '-created_at'
        )
        matches = []
        for candidate in candidates.select_related('credential__certificate'):
            cert = candidate.credential.certificate
            if cert is None:
                continue
            certificate = x509.load_pem_x509_certificate(cert.cert_pem.encode())
            try:
                san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            except x509.ExtensionNotFound:
                continue
            if ref.idevid_ref in san.get_values_for_type(x509.UniformResourceIdentifier):
                matches.append(candidate)
        target = None
        if ref.dev_owner_id_certificate_id is not None:
            target = candidates.filter(credential__certificate_id=ref.dev_owner_id_certificate_id).first()
        if target is None:
            target = matches[0] if matches else candidates.first()
        if target is None:
            ref.delete()
            continue
        ref.dev_owner_id_id = target.pk
        ref.dev_owner_id_certificate_id = target.credential.certificate_id
        ref.save(update_fields=['dev_owner_id', 'dev_owner_id_certificate'])
        for candidate in matches:
            if candidate.pk != target.pk:
                renewed_refs.append(  # noqa: PERF401
                    reference(
                        dev_owner_id_id=candidate.pk,
                        idevid_ref=ref.idevid_ref,
                        dev_owner_id_certificate_id=candidate.credential.certificate_id,
                    )
                )
    reference.objects.bulk_create(renewed_refs)
    # Drain deferred certificate foreign-key checks before altering this table on PostgreSQL.
    schema_editor.connection.check_constraints()


class Migration(migrations.Migration):
    """Apply the PKI changes for Trustpoint 1.0.1."""

    dependencies: ClassVar[list[Any]] = [
        ('onboarding', '0003_tp_v1_0_1'),
        ('pki', '0002_initial'),
    ]

    operations: ClassVar[list[Any]] = [
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
                help_text='Empty for imported DevOwnerID credentials without an issuance profile.',
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='+',
                to='pki.certificateprofilemodel',
            ),
        ),
        migrations.RunPython(
            code=link_existing_profiles,
            reverse_code=restore_profile_labels,
        ),
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
        migrations.AlterField(
            model_name='certificateprofilemodel',
            name='credential_type',
            field=models.CharField(
                choices=[
                    ('application', 'Application Credential'),
                    ('domain', 'Domain Credential'),
                    ('traceability_credential', 'Traceability Credential'),
                ],
                default='application',
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name='credentialmodel',
            name='credential_type',
            field=models.IntegerField(
                choices=[
                    (0, 'Trustpoint TLS Server'),
                    (1, 'Root CA'),
                    (2, 'Issuing CA'),
                    (3, 'Issued Credential'),
                    (4, 'DevOwnerID'),
                    (5, 'Signer'),
                    (6, 'SCEP Server'),
                    (7, 'Traceability Credential'),
                ],
                verbose_name='Credential Type',
            ),
        ),
        migrations.AddField(
            model_name='camodel',
            name='ca_role',
            field=models.IntegerField(
                choices=[(0, 'Issuing CA'), (1, 'Management CA')],
                db_index=True,
                default=0,
                help_text='Issuing CAs serve endpoints; management CAs only issue Trustpoint management certificates.',
                verbose_name='CA Role',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ('ca_role', 0), models.Q(('ca_role', 1), ('ca_type__in', [2, 3, 4, 5, 6, 7, 8])), _connector='OR'
                ),
                name='management_ca_role_constraint',
                violation_error_message='Management CAs cannot use this CA type',
            ),
        ),
        migrations.RunPython(
            code=mark_builtin_management_cas,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='idevidreferencemodel',
            name='dev_owner_id',
            field=models.ForeignKey(
                db_constraint=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='idevid_ref_set',
                to='pki.remoteissuedcredentialmodel',
            ),
        ),
        migrations.RunPython(
            code=fold_owner_credentials,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name='idevidreferencemodel',
            name='dev_owner_id',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='idevid_ref_set',
                to='pki.remoteissuedcredentialmodel',
            ),
        ),
        # Retain the legacy owner column/table for compatibility with the previous release.
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RemoveField(
                    model_name='remoteissuedcredentialmodel',
                    name='owner_credential',
                ),
                migrations.DeleteModel(
                    name='OwnerCredentialModel',
                ),
            ],
        ),
        migrations.RemoveConstraint(
            model_name='camodel',
            name='ca_mode_constraint',
        ),
        migrations.RemoveConstraint(
            model_name='camodel',
            name='management_ca_role_constraint',
        ),
        migrations.AlterField(
            model_name='camodel',
            name='ca_type',
            field=models.IntegerField(
                blank=True,
                choices=[
                    (-1, 'Keyless CA'),
                    (0, 'Auto-Generated Root (Legacy)'),
                    (1, 'Auto-Generated (Legacy)'),
                    (2, 'Local-Legacy Software'),
                    (3, 'Local-Managed Backend'),
                    (4, 'Remote-EST-RA'),
                    (5, 'Remote-CMP-RA'),
                    (6, 'Remote-Issuing-EST'),
                    (7, 'Remote-Issuing-CMP'),
                    (8, 'Remote-Issuing-CSR'),
                    (9, 'Self-Signed'),
                ],
                help_text='Type of CA - KEYLESS for keyless CAs',
                null=True,
                verbose_name='CA Type',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    models.Q(('ca_type', -1), ('certificate__isnull', False), ('credential__isnull', True)),
                    models.Q(('ca_type__in', [4, 5]), ('credential__isnull', True)),
                    models.Q(
                        ('ca_type__in', [0, 1, 2, 3, 6, 7, 8, 9]),
                        ('certificate__isnull', True),
                        ('credential__isnull', False),
                    ),
                    _connector='OR',
                ),
                name='ca_mode_constraint',
                violation_error_message='Invalid CA configuration',
            ),
        ),
        migrations.AddConstraint(
            model_name='camodel',
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ('ca_role', 0), models.Q(('ca_role', 1), ('ca_type__in', [2, 3, 4, 5, 6, 7, 8, 9])), _connector='OR'
                ),
                name='management_ca_role_constraint',
                violation_error_message='Management CAs cannot use this CA type',
            ),
        ),
    ]
