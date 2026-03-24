"""CMP certConf operation processor classes."""

from cmp.util import PKIFailureInfo
from request.request_context import BaseRequestContext, CmpCertConfRequestContext
from trustpoint.logger import LoggerMixin

from .base import AbstractOperationProcessor
from .revoke_cert import CertificateRevocationProcessor

# PKIStatus value 2 = "rejection" per RFC 4210 Section 5.2.3.
_PKI_STATUS_REJECTION = 2


class CertConfProcessor(AbstractOperationProcessor, LoggerMixin):
    """Operation processor for CMP certConf messages.

    Handles the back-end reaction to a certificate confirmation:

    * **Accepted** (``cert_conf_status == 0`` or absent): no CA operation is
      required — the :class:`~request.message_responder.cmp.CmpPkiConfResponder`
      sends the pkiConf reply.
    * **Rejected** (``cert_conf_status == 2``): the CA MUST revoke the
      just-issued certificate per RFC 9483 §5.1.2.  The authorization step is
      responsible for setting ``context.credential_to_revoke`` prior to
      reaching this processor.
    """

    def process_operation(self, context: BaseRequestContext) -> None:
        """Process the certConf operation."""
        if not isinstance(context, CmpCertConfRequestContext):
            exc_msg = 'CertConfProcessor requires a CmpCertConfRequestContext.'
            raise TypeError(exc_msg)

        if context.cert_conf_status != _PKI_STATUS_REJECTION:
            self.logger.info(
                'certConf received for certReqId=%s — status accepted. No CA operation required.',
                context.cert_req_id,
            )
            return

        if context.credential_to_revoke is None:
            exc_msg = (
                'certConf rejection received but credential_to_revoke is not set. '
                'Cannot revoke certificate.'
            )
            self.logger.error(exc_msg)
            context.error(exc_msg, http_status=500, cmp_code=PKIFailureInfo.SYSTEM_FAILURE)
            raise ValueError(exc_msg)

        self.logger.info(
            'certConf rejection for certReqId=%s — revoking credential %s.',
            context.cert_req_id,
            context.credential_to_revoke.common_name,
        )
        CertificateRevocationProcessor().process_operation(context)
