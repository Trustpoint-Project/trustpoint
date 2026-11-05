# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Report ambiguous SCEP ownership without disclosing challenge material or digests."""

from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError

from onboarding.models import NoOnboardingConfigModel, OnboardingConfigModel


class Command(BaseCommand):
    """Check both configuration tables, including retained consumed authorization."""

    help = 'Report duplicate SCEP challenge ownership without printing challenges or lookup digests.'

    def handle(self, **_options: object) -> None:
        """Report affected configuration records and fail until duplicates are resolved."""
        owners: dict[str, list[str]] = defaultdict(list)
        for model in (OnboardingConfigModel, NoOnboardingConfigModel):
            for pk, digest in model.objects.exclude(scep_challenge_digest='').values_list(
                'pk', 'scep_challenge_digest'
            ):
                owners[digest].append(f'{model.__name__}:{pk}')
        duplicates = [records for records in owners.values() if len(records) > 1]
        for records in duplicates:
            self.stdout.write('Duplicate SCEP ownership: ' + ', '.join(records))
        if duplicates:
            message = 'Resolve duplicate SCEP ownership before assigning custom challenges.'
            raise CommandError(message)
        self.stdout.write(self.style.SUCCESS('No duplicate SCEP challenge ownership found.'))
