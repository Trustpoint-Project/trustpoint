"""Tests for CMP-specific authorization components."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch

import pytest

from request.authorization.cmp import (
    CmpAuthorization,
    CmpCertConfAuthorization,
    CmpOperationAuthorization,
    CmpPollAuthorization,
    CmpRevocationAuthorization,
)
from request.authorization.base import ProtocolAuthorization
from request.request_context import (
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpPollRequestContext,
    CmpRevocationRequestContext,
)


# ---------------------------------------------------------------------------
# CmpRevocationAuthorization
# ---------------------------------------------------------------------------


class TestCmpRevocationAuthorization:
    """Tests for CmpRevocationAuthorization.authorize."""

    def test_non_revocation_operation_is_skipped(self) -> None:
        """Operations other than 'revocation' are passed through without any check."""
        ctx = Mock()
        ctx.operation = 'initialization'
        CmpRevocationAuthorization().authorize(ctx)  # must not raise

    def test_wrong_context_type_raises_type_error(self) -> None:
        """A revocation operation on a non-CmpRevocationRequestContext raises TypeError."""
        ctx = Mock(spec=CmpBaseRequestContext)
        ctx.operation = 'revocation'
        with pytest.raises(TypeError, match='CmpRevocationAuthorization requires'):
            CmpRevocationAuthorization().authorize(ctx)

    def test_missing_serial_number_raises_value_error(self) -> None:
        """Missing cert_serial_number raises ValueError and sets 403 on context."""
        ctx = CmpRevocationRequestContext(operation='revocation')
        ctx.cert_serial_number = None
        ctx.client_certificate = Mock()
        ctx.domain = Mock()
        with pytest.raises(ValueError, match='Certificate serial number is missing'):
            CmpRevocationAuthorization().authorize(ctx)
        assert ctx.http_response_status == 403

    def test_missing_client_certificate_raises_value_error(self) -> None:
        """Missing client_certificate raises ValueError."""
        ctx = CmpRevocationRequestContext(operation='revocation')
        ctx.cert_serial_number = 'ABCD1234'
        ctx.client_certificate = None
        ctx.domain = Mock()
        with pytest.raises(ValueError, match='Client certificate is missing'):
            CmpRevocationAuthorization().authorize(ctx)

    def test_missing_domain_raises_value_error(self) -> None:
        """Missing domain raises ValueError."""
        ctx = CmpRevocationRequestContext(operation='revocation')
        ctx.cert_serial_number = 'ABCD1234'
        ctx.client_certificate = Mock()
        ctx.domain = None
        with pytest.raises(ValueError, match='Domain information is missing'):
            CmpRevocationAuthorization().authorize(ctx)

    def test_unknown_signer_cert_raises_value_error(self) -> None:
        """Signer cert not in issued credentials raises ValueError."""
        ctx = CmpRevocationRequestContext(operation='revocation')
        ctx.cert_serial_number = 'ABCD1234'
        ctx.client_certificate = Mock()
        ctx.domain = Mock()

        from pki.models import IssuedCredentialModel
        with patch.object(
            IssuedCredentialModel,
            'get_credential_for_certificate',
            side_effect=IssuedCredentialModel.DoesNotExist,
        ):
            with pytest.raises(ValueError, match='Signer certificate is not associated'):
                CmpRevocationAuthorization().authorize(ctx)


# ---------------------------------------------------------------------------
# CmpCertConfAuthorization
# ---------------------------------------------------------------------------


class TestCmpCertConfAuthorization:
    """Tests for CmpCertConfAuthorization.authorize."""

    def test_non_certconf_operation_is_skipped(self) -> None:
        """Operations other than certconf/initialization/certification are no-ops."""
        ctx = Mock()
        ctx.operation = 'revocation'
        CmpCertConfAuthorization().authorize(ctx)  # must not raise

    def test_non_certconf_context_type_is_skipped(self) -> None:
        """Even a certconf operation is skipped if context is not CmpCertConfRequestContext."""
        ctx = Mock(spec=CmpBaseRequestContext)
        ctx.operation = 'certconf'
        CmpCertConfAuthorization().authorize(ctx)  # must not raise

    def test_accepted_status_is_a_noop(self) -> None:
        """cert_conf_status == 0 (accepted) does not trigger credential lookup."""
        ctx = CmpCertConfRequestContext(operation='certconf', cert_conf_status=0)
        CmpCertConfAuthorization().authorize(ctx)  # must not raise
        assert ctx.credential_to_revoke is None

    def test_absent_status_is_a_noop(self) -> None:
        """cert_conf_status == None (no statusInfo) does not trigger credential lookup."""
        ctx = CmpCertConfRequestContext(operation='certconf', cert_conf_status=None)
        CmpCertConfAuthorization().authorize(ctx)
        assert ctx.credential_to_revoke is None

    def test_rejection_without_cert_hash_raises_value_error(self) -> None:
        """Rejection (status == 2) without certHash raises ValueError."""
        ctx = CmpCertConfRequestContext(operation='certconf', cert_conf_status=2, cert_hash=None)
        with pytest.raises(ValueError, match='certHash is missing'):
            CmpCertConfAuthorization().authorize(ctx)

    def test_rejection_with_unknown_cert_hash_raises_value_error(self) -> None:
        """Rejection with certHash that matches no issued credential raises ValueError."""
        cert_hash = b'\xde\xad\xbe\xef' * 8
        ctx = CmpCertConfRequestContext(operation='certconf', cert_conf_status=2, cert_hash=cert_hash)

        from pki.models import IssuedCredentialModel
        mock_qs = Mock()
        mock_qs.select_related.return_value.first.return_value = None
        with patch.object(IssuedCredentialModel.objects, 'filter', return_value=mock_qs):
            with pytest.raises(ValueError, match='no issued credential found'):
                CmpCertConfAuthorization().authorize(ctx)

    def test_rejection_with_known_cert_hash_sets_credential_to_revoke(self) -> None:
        """Rejection with a matching certHash populates context.credential_to_revoke."""
        cert_hash = bytes.fromhex('aa' * 32)
        ctx = CmpCertConfRequestContext(operation='certconf', cert_conf_status=2, cert_hash=cert_hash)

        mock_cred = Mock()
        mock_cred.common_name = 'test-device-cert'
        from pki.models import IssuedCredentialModel
        mock_qs = Mock()
        mock_qs.select_related.return_value.first.return_value = mock_cred
        with patch.object(IssuedCredentialModel.objects, 'filter', return_value=mock_qs):
            CmpCertConfAuthorization().authorize(ctx)

        assert ctx.credential_to_revoke is mock_cred


# ---------------------------------------------------------------------------
# CmpPollAuthorization
# ---------------------------------------------------------------------------


class TestCmpPollAuthorization:
    """Tests for CmpPollAuthorization.authorize."""

    def test_non_poll_context_is_skipped(self) -> None:
        """Non-CmpPollRequestContext is silently skipped."""
        ctx = Mock(spec=CmpBaseRequestContext)
        CmpPollAuthorization().authorize(ctx)  # must not raise

    def test_non_pollreq_body_type_is_skipped(self) -> None:
        """CmpPollRequestContext with body type != pollReq is skipped."""
        ctx = CmpPollRequestContext(cmp_body_type='ir')
        CmpPollAuthorization().authorize(ctx)  # must not raise

    def test_missing_transaction_id_raises_value_error(self) -> None:
        """pollReq without a transactionID raises ValueError."""
        ctx = CmpPollRequestContext(cmp_body_type='pollReq', cmp_transaction_id=None)
        with pytest.raises(ValueError, match='missing a transactionID'):
            CmpPollAuthorization().authorize(ctx)

    def test_unknown_transaction_id_raises_value_error(self) -> None:
        """pollReq for a transaction that does not exist raises ValueError."""
        ctx = CmpPollRequestContext(cmp_body_type='pollReq', cmp_transaction_id='unknown-tx')
        from request.cmp_transaction_state import CmpTransactionState
        with patch.object(CmpTransactionState, 'get_by_transaction_id', return_value=None):
            with pytest.raises(ValueError, match='No CMP transaction found'):
                CmpPollAuthorization().authorize(ctx)

    @pytest.mark.django_db
    def test_valid_poll_request_hydrates_context(self) -> None:
        """A valid pollReq loads the stored transaction into the context."""
        from cmp.models import CmpTransactionModel
        transaction = CmpTransactionModel.objects.create(
            transaction_id='deadbeef01',
            operation='initialization',
            request_body_type='ir',
            domain_name='test-domain',
            cert_profile='domain_credential',
            cert_req_id=0,
            request_der=b'cmp-ir-request',
            implicit_confirm=True,
            status=CmpTransactionModel.Status.WAITING,
            detail='Pending workflow approval.',
            check_after_seconds=5,
        )
        ctx = CmpPollRequestContext(
            protocol='cmp',
            cmp_body_type='pollReq',
            cmp_transaction_id='deadbeef01',
            poll_cert_req_id=0,
        )
        CmpPollAuthorization().authorize(ctx)
        assert ctx.operation == 'initialization'
        assert ctx.cert_profile_str == 'domain_credential'
        assert ctx.implicit_confirm is True
        assert ctx.cmp_transaction == transaction


# ---------------------------------------------------------------------------
# CmpOperationAuthorization
# ---------------------------------------------------------------------------


class TestCmpOperationAuthorization:
    """Tests for CmpOperationAuthorization.authorize."""

    def test_wrong_context_type_raises_type_error(self) -> None:
        """Non-CmpBaseRequestContext raises TypeError."""
        from request.request_context import BaseRequestContext
        ctx = Mock(spec=BaseRequestContext)
        with pytest.raises(TypeError, match='CmpOperationAuthorization requires'):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_missing_operation_raises_value_error(self) -> None:
        """None operation raises ValueError."""
        ctx = CmpBaseRequestContext(operation=None)
        with pytest.raises(ValueError, match='Operation information is missing'):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_empty_operation_raises_value_error(self) -> None:
        """Empty-string operation raises ValueError."""
        ctx = CmpBaseRequestContext(operation='')
        with pytest.raises(ValueError, match='Operation information is missing'):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_disallowed_operation_raises_value_error(self) -> None:
        """Operation not in allowed_operations raises ValueError."""
        ctx = CmpBaseRequestContext(operation='revocation')
        with pytest.raises(ValueError, match="Unauthorized operation: 'revocation'"):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_missing_parsed_message_raises_value_error(self) -> None:
        """Allowed operation with non-PKIMessage parsed_message raises ValueError."""
        ctx = CmpBaseRequestContext(operation='initialization')
        ctx.parsed_message = None  # not a PKIMessage
        with pytest.raises(ValueError, match='Parsed message is missing'):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_body_type_mismatch_raises_value_error(self) -> None:
        """Body type that does not match the declared operation raises ValueError."""
        from pyasn1_modules.rfc4210 import PKIMessage
        msg = MagicMock()
        msg.__class__ = PKIMessage  # makes isinstance(msg, PKIMessage) return True
        msg['body'].getName.return_value = 'cr'  # CR body, but operation is 'initialization'

        ctx = CmpBaseRequestContext(operation='initialization')
        ctx.parsed_message = msg
        with pytest.raises(ValueError, match='Expected CMP initialization body'):
            CmpOperationAuthorization(['initialization']).authorize(ctx)

    def test_matching_ir_body_passes(self) -> None:
        """initialization operation with IR body passes without raising."""
        from pyasn1_modules.rfc4210 import PKIMessage
        msg = MagicMock()
        msg.__class__ = PKIMessage
        msg['body'].getName.return_value = 'ir'

        ctx = CmpBaseRequestContext(operation='initialization')
        ctx.parsed_message = msg
        CmpOperationAuthorization(['initialization']).authorize(ctx)  # must not raise

    def test_matching_cr_body_passes(self) -> None:
        """certification operation with CR body passes without raising."""
        from pyasn1_modules.rfc4210 import PKIMessage
        msg = MagicMock()
        msg.__class__ = PKIMessage
        msg['body'].getName.return_value = 'cr'

        ctx = CmpBaseRequestContext(operation='certification')
        ctx.parsed_message = msg
        CmpOperationAuthorization(['certification']).authorize(ctx)  # must not raise


# ---------------------------------------------------------------------------
# CmpAuthorization (composite)
# ---------------------------------------------------------------------------


class TestCmpAuthorization:
    """Tests for CmpAuthorization composite initialization."""

    def test_default_initialization_has_eight_components(self) -> None:
        """CmpAuthorization with default args creates 8 authorization components."""
        auth = CmpAuthorization()
        assert len(auth.components) == 8

    def test_protocol_component_is_cmp(self) -> None:
        """The ProtocolAuthorization component is configured for the 'cmp' protocol."""
        auth = CmpAuthorization()
        proto_comp = next(c for c in auth.components if isinstance(c, ProtocolAuthorization))
        assert proto_comp.allowed_protocols == ['cmp']

    def test_custom_allowed_operations_are_forwarded(self) -> None:
        """Passing custom allowed_operations is reflected in CmpOperationAuthorization."""
        auth = CmpAuthorization(allowed_operations=['revocation'])
        op_comp = next(c for c in auth.components if isinstance(c, CmpOperationAuthorization))
        assert op_comp.allowed_operations == ['revocation']

    def test_default_allowed_operations(self) -> None:
        """Default allowed operations are certification and initialization."""
        auth = CmpAuthorization()
        op_comp = next(c for c in auth.components if isinstance(c, CmpOperationAuthorization))
        assert set(op_comp.allowed_operations) == {'certification', 'initialization'}
