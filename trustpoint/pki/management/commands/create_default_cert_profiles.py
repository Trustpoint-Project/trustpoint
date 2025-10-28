"""Django management command for creating default certificate profiles."""

from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand
from pki.models.cert_profile import CertificateProfileModel
from pki.util.cert_profile import CertProfileModel as CertProfilePydanticModel
from pydantic import ValidationError


class Command(BaseCommand):
    """Creates default certificate profiles from JSON files in ../default_certificate_profiles."""

    help = 'Creates default certificate profiles.'

    def handle(self, *_args: tuple[str], **_kwargs: dict[str, str]) -> None:
        """Creates default certificate profiles."""
        default_profiles_path = Path(__file__).parent.parent.parent / 'default_certificate_profiles'
        print(f'Loading default certificate profiles from: {default_profiles_path}')
        profile_files = default_profiles_path.glob('*.json')

        for profile_file in profile_files:
            unique_name = profile_file.stem
            with profile_file.open('r', encoding='utf-8') as f:
                profile_json = f.read()

            # Check if valid JSON Profile
            try:
                profile_dict = json.loads(profile_json)
                CertProfilePydanticModel.model_validate(profile_dict)
            except (ValidationError, ValueError) as e:
                print(f'Invalid JSON certificate profile in {profile_file}: {e}')
                continue

            _obj, created = CertificateProfileModel.objects.get_or_create(
                unique_name=unique_name,
                defaults={'profile_json': profile_json}
            )

            if created:
                print(f'Created certificate profile: {unique_name}')
            else:
                print(f'Certificate profile already exists: {unique_name}')
