# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""CMP certConf operation processor classes."""

from django.db import transaction
from django.utils import timezone

from cmp.confirmation import (
    confirmation_is_due,
    expire_confirmation,
    locked_confirmation,
    require_awaiting_confirmation,
)
from cmp.models import CmpTransactionModel
from cmp.util import PKI_STATUS_REJECTION, PKIFailureInfo
from request.request_context import BaseRequestContext, CmpCertConfRequestContext
from request.security_hardening import retire_bootstrap_credential_after_certconf
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor
from .revoke_cert import CertificateRevocationProcessor


class CertConfProcessor(AbstractOperationProcessor, LoggerMixin):
    """Operation processor for CMP certConf messages.

    Handles the back-end reaction to a certificate confirmation:

    * **Accepted** (``cert_conf_status == 0`` or absent): no CA operation is
      required — the :class:`~request.message_responder.cmp.CmpPkiConfResponder`
      sends the pkiConf reply.
    * **Rejected** (``cert_conf_status == 2``): Trustpoint's rejection policy revokes the
      just-issued certificate. The authorization step is
      responsible for setting ``context.credential_to_revoke`` prior to
      reaching this processor.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certConf operation."""
        if not isinstance(context, CmpCertConfRequestContext):
            exc_msg = 'CertConfProcessor requires a CmpCertConfRequestContext.'
            raise TypeError(exc_msg)

        if isinstance(context.cmp_transaction, CmpTransactionModel):
            transaction_pk = context.cmp_transaction.pk
            if confirmation_is_due(context.cmp_transaction, timezone.now()):
                expire_confirmation(transaction_pk)
            with locked_confirmation(transaction_pk) as (record, _config):
                require_awaiting_confirmation(record)
                context.cmp_transaction = record
                self._process_confirmation(context)
            return

        self._process_confirmation(context)

    def _process_confirmation(self, context: CmpCertConfRequestContext) -> None:
        """Apply an authenticated confirmation while its transaction is locked."""
        if context.cert_conf_status != PKI_STATUS_REJECTION:
            self.logger.info(
                'certConf received for certReqId=%s — status accepted. No CA operation required.',
                context.cert_req_id,
            )
            with transaction.atomic():
                retire_bootstrap_credential_after_certconf(context)
                self._mark_confirmed(context)
            return

        if context.credential_to_revoke is None:
            exc_msg = 'certConf rejection received but credential_to_revoke is not set. Cannot revoke certificate.'
            self.logger.error(exc_msg)
            context.error(exc_msg, http_status=500, cmp_code=PKIFailureInfo.SYSTEM_FAILURE)
            raise ValueError(exc_msg)

        self.logger.info(
            'certConf rejection for certReqId=%s — revoking credential %s.',
            context.cert_req_id,
            context.credential_to_revoke.common_name,
        )
        CertificateRevocationProcessor().process_operation(context)
        self._mark_confirmed(context)

    @staticmethod
    def _mark_confirmed(context: CmpCertConfRequestContext) -> None:
        """Record confirmation only after acceptance or successful rejection revocation."""
        if isinstance(context.cmp_transaction, CmpTransactionModel):
            context.cmp_transaction.confirmed_at = timezone.now()
            context.cmp_transaction.save(update_fields=['confirmed_at'])
