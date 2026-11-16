# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Keep the user authentication profile out of automatic device-domain defaults."""

from django.db import migrations


def remove_user_profile_domain_default(apps, schema_editor):
    profiles = apps.get_model('pki', 'CertificateProfileModel').objects.using(schema_editor.connection.alias)
    profiles.filter(unique_name='user_client').update(is_default=False)


class Migration(migrations.Migration):
    dependencies = [('management', '0008_default_user_certificate_profile')]

    operations = [migrations.RunPython(remove_user_profile_domain_default, migrations.RunPython.noop)]
