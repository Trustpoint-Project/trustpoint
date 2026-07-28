# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management command to create service accounts and API keys."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

from users.models import ServiceAccountCredential, TrustpointUser

if TYPE_CHECKING:
    from argparse import ArgumentParser


class Command(BaseCommand):
    """Create a service account with API key credentials."""

    help = 'Create a service account with API key credentials for API integrations'

    def add_arguments(self, parser: ArgumentParser) -> None:
        """Add command arguments."""
        parser.add_argument(
            'username',
            type=str,
            help='Username for the service account',
        )
        parser.add_argument(
            '--role',
            type=str,
            default='Default',
            help='Role/group name for the service account (default: Default)',
        )
        parser.add_argument(
            '--description',
            type=str,
            default='',
            help='Description for the API key credential',
        )
        parser.add_argument(
            '--expires-days',
            type=int,
            help='Number of days until the credential expires (optional)',
        )

    def handle(self, *args: object, **options: object) -> None:
        """Execute the command."""
        username = options['username']
        role_name = options['role']
        description = options['description']
        expires_days = options.get('expires_days')

        try:
            role = Group.objects.get(name=role_name)
        except Group.DoesNotExist:
            self.stdout.write(self.style.ERROR(f"Role '{role_name}' does not exist"))
            return

        try:
            service_account = TrustpointUser.objects.create(
                username=username,
                account_type=TrustpointUser.AccountType.SERVICE,
                role=role,
                is_active=True,
            )
            service_account.set_unusable_password()
            service_account.save()

            self.stdout.write(self.style.SUCCESS(
                f"Created service account: {username}"
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to create service account: {e}"))
            return

        client_id = ServiceAccountCredential.generate_client_id()
        secret = ServiceAccountCredential.generate_secret()
        hashed_secret = make_password(secret)

        expires_at = None
        if expires_days:
            from django.utils import timezone
            from datetime import timedelta
            expires_at = timezone.now() + timedelta(days=expires_days)

        # Create the credential
        try:
            credential = ServiceAccountCredential.objects.create(
                service_account=service_account,
                client_id=client_id,
                hashed_secret=hashed_secret,
                description=description or f'API key for {username}',
                expires_at=expires_at,
            )

            self.stdout.write(self.style.SUCCESS('\n' + '=' * 70))
            self.stdout.write(self.style.SUCCESS('Service Account Created Successfully!'))
            self.stdout.write(self.style.SUCCESS('=' * 70))
            self.stdout.write(f'\nUsername:    {service_account.username}')
            self.stdout.write(f'Account Type: {service_account.get_account_type_display()}')
            self.stdout.write(f'Role:        {service_account.role.name}')
            self.stdout.write(f'\nClient ID:   {credential.client_id}')
            self.stdout.write(f'Secret:      {secret}')
            if expires_at:
                self.stdout.write(f'Expires:     {expires_at}')
            self.stdout.write(self.style.WARNING(
                '\n⚠️  IMPORTANT: Save the secret now! It cannot be retrieved later.'
            ))
            self.stdout.write(self.style.SUCCESS('\nAuthentication Header Format:'))
            self.stdout.write(f'  Authorization: ServiceAccount {credential.client_id}:{secret}')
            self.stdout.write(self.style.SUCCESS('=' * 70 + '\n'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to create API key: {e}"))
            # Clean up the service account if credential creation failed
            service_account.delete()
