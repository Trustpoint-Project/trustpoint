import django.db.models.deletion
import management.models.certificate_authentication
from django.db import migrations, models


def install_default_user_profile(apps, schema_editor):
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


class Migration(migrations.Migration):
    dependencies = [
        ('management', '0007_user_certificate_profile'),
        ('pki', '0006_self_signed_ca_type'),
    ]

    operations = [
        migrations.RunPython(install_default_user_profile, migrations.RunPython.noop),
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
    ]
