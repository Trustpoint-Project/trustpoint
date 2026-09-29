# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Lifecycle operations for the CA hierarchy used for management certificates."""

from __future__ import annotations

from io import StringIO

from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from pki.management.commands.create_management_ca import ISSUING_CA_NAME, ROOT_CA_NAME
from pki.models import CaModel


class ManagementCAService:
    """Manage the root and issuing CA together, preserving existing CA deletion protections."""

    @staticmethod
    def get_hierarchy(*, lock: bool = False) -> tuple[CaModel | None, CaModel | None]:
        """Load only the named management CAs, optionally locking them for a lifecycle operation."""
        queryset = CaModel.objects.filter(unique_name__in=(ROOT_CA_NAME, ISSUING_CA_NAME)).order_by('pk')
        if lock:
            queryset = queryset.select_for_update()
        cas = {ca.unique_name: ca for ca in queryset}
        return cas.get(ROOT_CA_NAME), cas.get(ISSUING_CA_NAME)

    @staticmethod
    def is_complete(root_ca: CaModel | None, issuing_ca: CaModel | None) -> bool:
        """Return whether both CAs have credentials and form the expected hierarchy."""
        return bool(
            root_ca is not None and issuing_ca is not None
            and root_ca.parent_ca_id is None and issuing_ca.parent_ca_id == root_ca.pk
            and root_ca.credential_id is not None and issuing_ca.credential_id is not None
        )

    @classmethod
    @transaction.atomic
    def apply(cls, action: str, *, root_ca_id: int | None, issuing_ca_id: int | None) -> None:
        """Apply an explicit action only to the hierarchy the administrator was shown."""
        if action not in ('generate', 'replace', 'delete'):
            raise ValidationError(_('Choose a valid management CA action.'))
        root_ca, issuing_ca = cls.get_hierarchy(lock=True)
        current_ids = (root_ca.pk if root_ca else None, issuing_ca.pk if issuing_ca else None)
        if current_ids != (root_ca_id, issuing_ca_id):
            raise ValidationError(_('The management CA has changed. Review the current state and try again.'))

        if action == 'generate':
            if root_ca is not None or issuing_ca is not None:
                raise ValidationError(_('A management CA already exists. Use Generate new CA to replace it.'))
        else:
            if root_ca is None and issuing_ca is None:
                raise ValidationError(_('There is no management CA to replace or delete.'))
            if action == 'replace' and not cls.is_complete(root_ca, issuing_ca):
                raise ValidationError(_('The management CA is incomplete. Delete it before generating a new one.'))
            cls._delete_hierarchy(root_ca, issuing_ca)

        if action in ('generate', 'replace'):
            call_command('create_management_ca', stdout=StringIO(), stderr=StringIO())

    @staticmethod
    def _delete_hierarchy(root_ca: CaModel | None, issuing_ca: CaModel | None) -> None:
        """Delete children first and clean up their certificates and dedicated chain truststores."""
        root_id = root_ca.pk if root_ca else None
        if (root_ca and root_ca.parent_ca_id is not None) or (
            issuing_ca and issuing_ca.parent_ca_id != root_id
        ):
            raise ValidationError(_('The management CA hierarchy is inconsistent and cannot be deleted here.'))

        for ca in (issuing_ca, root_ca):
            if ca is None:
                continue
            certificates = list(ca.credential.certificates.all()) if ca.credential else []
            chain_truststore = ca.chain_truststore
            ca.delete()
            if chain_truststore is not None:
                chain_truststore.delete()
            for certificate in certificates:
                certificate.delete()
