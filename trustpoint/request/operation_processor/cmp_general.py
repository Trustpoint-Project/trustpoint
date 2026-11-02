# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Read-only CMP support operations (RFC 9483 Section 4.3)."""

from typing import Never

from cryptography import x509

from cmp.util import PKIFailureInfo
from pki.models.ca_rollover import CaRolloverState
from pki.services.ca_rollover import CaRolloverService
from request.request_context import BaseRequestContext, CmpGeneralRequestContext

from .base import AbstractOperationProcessor

CA_CERTS_OID = '1.3.6.1.5.5.7.4.17'


class CmpGeneralProcessor(AbstractOperationProcessor):
    """Serve the requested domain's CA certificates without issuing a credential."""

    def process_operation(self, context: BaseRequestContext) -> None:
        """Validate the support request and collect available CA certificates."""
        if not isinstance(context, CmpGeneralRequestContext):
            msg = 'CmpGeneralProcessor requires a CmpGeneralRequestContext.'
            raise TypeError(msg)
        self._validate_request(context)
        if context.domain is None:
            self._reject(context, 'CMP CA certificate retrieval requires a domain.')

        ca = context.domain.issuing_ca
        context.ca_certificates = []
        if ca is None:
            return
        context.issuer_credential = ca.get_credential()
        if context.issuer_credential is None:
            self._reject(context, 'CMP CA certificate retrieval requires a local response signing credential.')

        certificates = [
            context.issuer_credential.get_certificate(),
            *context.issuer_credential.get_certificate_chain(),
        ]
        rollover = CaRolloverService.get_active_rollover(ca)
        if rollover and rollover.state == CaRolloverState.PREPARATION and rollover.new_issuing_ca:
            credential = rollover.new_issuing_ca.get_credential()
            if credential is not None:
                certificates.extend([credential.get_certificate(), *credential.get_certificate_chain()])
        for certificate in dict.fromkeys(certificates):
            try:
                if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    context.ca_certificates.append(certificate)
            except x509.ExtensionNotFound:
                continue

    @classmethod
    def _validate_request(cls, context: CmpGeneralRequestContext) -> None:
        message = context.parsed_message
        if message is None or message['body'].getName() != 'genm' or context.operation != 'getcacerts':
            msg = 'Expected a CMP getcacerts general message.'
            raise ValueError(msg)
        entries = message['body']['genm']
        if len(entries) != 1:
            cls._reject(context, 'CMP genm must contain exactly one InfoTypeAndValue.')
        if str(entries[0]['infoType']) != CA_CERTS_OID:
            cls._reject(context, 'Unsupported CMP general message infoType.')
        if entries[0]['infoValue'].hasValue():
            cls._reject(context, 'CMP id-it-caCerts request infoValue must be absent.')

    @staticmethod
    def _reject(context: CmpGeneralRequestContext, message: str) -> Never:
        context.error(message, http_status=400, cmp_code=PKIFailureInfo.BAD_REQUEST)
        raise ValueError(message)
