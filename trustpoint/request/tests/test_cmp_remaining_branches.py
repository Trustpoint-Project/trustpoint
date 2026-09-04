"""Focused coverage for defensive CMP request branches."""

from unittest.mock import Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import tag
from pyasn1_modules import rfc2459, rfc4210, rfc5280
from trustpoint_core.oid import HashAlgorithm, HmacAlgorithm

from cmp.models import CmpTransactionModel
from pki.models import IssuedCredentialModel
from pki.models.ca_rollover import CaRolloverState
from request.authorization.base import (
    CertificateProfileAuthorization,
    OnboardingDomainCredentialAuthorization,
    SecurityConfigAuthorization,
)
from request.authorization.cmp import (
    CmpCertConfAuthorization,
    CmpOperationAuthorization,
    CmpPollAuthorization,
    CmpRevocationAuthorization,
)
from request.message_parser.cmp import (
    CmpBodyValidation,
    CmpCertConfBodyValidation,
    CmpCertificateBodyValidation,
    CmpHeaderValidation,
    CmpPkiMessageParsing,
    CmpRevocationBodyValidation,
)
from request.message_parser.rfc9480 import PKIBody, PKIMessage
from request.message_responder.cmp import (
    CmpErrorMessageResponder,
    CmpMessageResponder,
    CmpTransactionResponder,
)
from request.request_context import (
    BaseCertificateRequestContext,
    CmpBaseRequestContext,
    CmpCertConfRequestContext,
    CmpPollRequestContext,
    CmpRevocationRequestContext,
)


def _message(body_type: str = 'ir') -> rfc4210.PKIMessage:
    message = rfc4210.PKIMessage()
    message['header']['pvno'] = 2
    message['header']['transactionID'] = b't' * 16
    message['header']['senderNonce'] = b'n' * 16
    message['body'][body_type].setComponentByPosition(0)
    return message


class TestCmpAuthorizationRemainingBranches:
    def test_revocation_rejects_invalid_domain_credential(self) -> None:
        context = CmpRevocationRequestContext(
            operation='revocation', cert_serial_number='1234', client_certificate=Mock(), domain=Mock(),
        )
        credential = Mock(
            credential=Mock(certificate_or_error=Mock(serial_number='5678')),
            is_valid_domain_credential=Mock(return_value=(False, 'expired')),
        )
        with patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=credential):
            with pytest.raises(ValueError, match='Signer certificate does not match'):
                CmpRevocationAuthorization().authorize(context)

    def test_revocation_authorizes_matching_domain_credential(self) -> None:
        device = Mock()
        context = CmpRevocationRequestContext(
            operation='revocation', cert_serial_number='1234', client_certificate=Mock(),
            domain=Mock(), device=device,
        )
        signer = Mock(
            credential=Mock(certificate_or_error=Mock(serial_number='5678')),
            device=device, is_valid_domain_credential=Mock(return_value=(True, None)),
        )
        target = Mock(common_name='target')
        with (
            patch.object(IssuedCredentialModel, 'get_credential_for_certificate', return_value=signer),
            patch.object(IssuedCredentialModel, 'get_credential_for_serial_number', return_value=target),
        ):
            CmpRevocationAuthorization().authorize(context)
        assert context.credential_to_revoke is target

    def test_certconf_rejects_unsupported_declared_hash(self) -> None:
        context = CmpCertConfRequestContext(
            operation='certconf', cert_conf_status=2, cert_hash=b'hash',
            cert_hash_algorithm_oid='1.2.3.4',
        )
        with pytest.raises(ValueError, match='unsupported'):
            CmpCertConfAuthorization().authorize(context)
        assert context.http_response_status == 403

    def test_certconf_rejects_disallowed_hash(self) -> None:
        context = CmpCertConfRequestContext(
            operation='certconf', cert_conf_status=2, cert_hash=b'hash',
            cert_hash_algorithm_oid=HashAlgorithm.MD5.dotted_string,
        )
        with pytest.raises(ValueError, match='not permitted'):
            CmpCertConfAuthorization().authorize(context)

    def test_poll_rejects_cert_id_and_domain_mismatches(self) -> None:
        context = CmpPollRequestContext(
            cmp_body_type='pollReq', cmp_transaction_id='tx', poll_cert_req_id=9,
            device=Mock(id=1), domain=Mock(id=2),
        )
        transaction = Mock(operation='initialization', cert_req_id=0, device_id=1, domain_id=3)
        with patch('request.authorization.cmp.CmpTransactionState.get_by_transaction_id', return_value=transaction):
            with pytest.raises(ValueError, match='certReqId mismatch'):
                CmpPollAuthorization().authorize(context)

        context.poll_cert_req_id = 0
        with patch('request.authorization.cmp.CmpTransactionState.get_by_transaction_id', return_value=transaction):
            with pytest.raises(ValueError, match='domain does not match'):
                CmpPollAuthorization().authorize(context)

    def test_operation_authorizes_revocation_certconf_and_poll(self) -> None:
        operations = (('revocation', 'rr'), ('certification', 'certConf'), ('initialization', 'pollReq'))
        for operation, body_type in operations:
            context = CmpBaseRequestContext(operation=operation, parsed_message=_message(body_type))
            with (
                patch('request.authorization.cmp.CmpRevocationAuthorization.authorize'),
                patch('request.authorization.cmp.CmpCertConfAuthorization.authorize'),
            ):
                CmpOperationAuthorization([operation]).authorize(context)


class TestAuthorizationPolicyBranches:
    def test_profile_rejects_no_onboarding_domain_profile(self) -> None:
        context = Mock(spec=BaseCertificateRequestContext)
        context.cert_profile_str = 'domain_credential'
        context.domain = Mock()
        context.device = Mock(onboarding_config=None, common_name='device')
        context.domain.get_allowed_cert_profile.return_value = Mock(credential_type='domain')
        with patch('request.authorization.base.ProfileValidator.validate'):
            with pytest.raises(ValueError, match='No-Onboarding Device'):
                CertificateProfileAuthorization().authorize(context)

    def test_onboarding_accepts_any_valid_domain_credential(self) -> None:
        context = Mock(spec=BaseCertificateRequestContext)
        context.device = Mock(onboarding_config=Mock())
        context.domain = None
        context.certificate_profile_model = Mock(unique_name='tls_server')
        queryset = Mock()
        queryset.select_related.return_value = [Mock(is_valid_domain_credential=Mock(return_value=(True, None)))]
        with patch('request.authorization.base.IssuedCredentialModel.objects.filter', return_value=queryset):
            OnboardingDomainCredentialAuthorization().authorize(context)

    def test_security_config_helpers_cover_empty_and_unknown_policies(self) -> None:
        component = SecurityConfigAuthorization()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(
            rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256(),
        )
        component._check_key_constraints(csr, Mock(rsa_minimum_key_size=0))
        component._check_signature_algorithm(csr, Mock(not_permitted_signature_algorithm_oids=['1.2.3']))
        component._check_ca_issuance(csr, Mock(allow_ca_issuance=True))
        assert component._hash_oid('SHA-256') == HashAlgorithm.SHA256.dotted_string


class TestCmpResponderRemainingBranches:
    def test_header_and_implicit_confirm_are_encoded(self) -> None:
        message = _message()
        sender_kid = rfc2459.KeyIdentifier(b'ski').subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )
        header = CmpMessageResponder._build_response_message_header(message, sender_kid, None)
        assert header['recipient'] == message['header']['sender']
        response = rfc4210.PKIMessage()
        response['header'] = header
        CmpMessageResponder._grant_implicit_confirm(response)
        assert len(response['header']['generalInfo']) == 1

    def test_transaction_detail_fallbacks_and_credential_resolution(self) -> None:
        for status, expected in (
            (CmpTransactionModel.Status.PROCESSING, 3),
            (CmpTransactionModel.Status.REJECTED, 2),
            (CmpTransactionModel.Status.CANCELLED, 2),
            (CmpTransactionModel.Status.FAILED, 2),
        ):
            result, detail = CmpTransactionResponder._detail_for_transaction_status(Mock(status=status, detail=None))
            assert result == expected
            assert detail

        credential = Mock()
        context = Mock(issuer_credential=credential)
        assert CmpTransactionResponder._resolve_issuer_credential(context) is credential
        context.issuer_credential = None
        context.cmp_transaction = Mock(issuer_credential=credential)
        assert CmpTransactionResponder._resolve_issuer_credential(context) is credential

    def test_error_message_uses_empty_sender_kid_without_ca(self) -> None:
        context = CmpBaseRequestContext(parsed_message=_message(), error_details='bad')
        with (
            patch.object(
                CmpErrorMessageResponder, '_sign_pki_message', side_effect=lambda pki_message, **_: pki_message,
            ),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'error'),
        ):
            CmpErrorMessageResponder._build_response(context)
        assert context.http_response_content == b'error'

    def test_rollover_chain_is_appended_in_preparation(self, device_instance) -> None:
        issuer = Mock()
        issuer.get_certificate.return_value = device_instance['cert']
        issuer.get_certificate_chain.return_value = []
        new_issuer = Mock()
        new_issuer.credential = Mock()
        new_issuer.credential.get_certificate.return_value = device_instance['cert']
        new_issuer.credential.get_certificate_chain.return_value = []
        rollover = Mock(
            state=CaRolloverState.PREPARATION,
            new_issuing_ca=new_issuer,
        )
        context = Mock(domain=Mock(issuing_ca=Mock()))
        with patch('request.message_responder.cmp.CaRolloverService.get_active_rollover', return_value=rollover):
            chain = CmpMessageResponder.build_certificate_chain_with_rollover(issuer, context)
        assert chain == [device_instance['cert'], device_instance['cert']]

    def test_transaction_credential_falls_back_to_domain_issuing_ca(self) -> None:
        credential = Mock()
        context = Mock(issuer_credential=None, cmp_transaction=None)
        context.domain = Mock(issuing_ca=Mock())
        context.domain.issuing_ca.get_credential.return_value = credential
        assert CmpTransactionResponder._resolve_issuer_credential(context) is credential

    def test_error_response_handles_missing_domain_credential(self) -> None:
        context = CmpBaseRequestContext(parsed_message=_message(), error_details='bad', domain=Mock())
        context.domain.get_issuing_ca_or_value_error.side_effect = ValueError('missing')
        with (
            patch.object(
                CmpErrorMessageResponder, '_sign_pki_message', side_effect=lambda pki_message, **_: pki_message,
            ),
            patch('request.message_responder.cmp.encoder.encode', return_value=b'error'),
        ):
            CmpErrorMessageResponder._build_response(context)
        assert context.http_response_content == b'error'

    def test_rollover_chain_ignores_non_preparation_rollover(self) -> None:
        issuer = Mock()
        issuer.get_certificate_chain.return_value = []
        rollover = Mock(state=CaRolloverState.COMPLETED, new_issuing_ca=Mock())
        context = Mock(domain=Mock(issuing_ca=Mock()))
        with patch('request.message_responder.cmp.CaRolloverService.get_active_rollover', return_value=rollover):
            chain = CmpMessageResponder.build_certificate_chain_with_rollover(issuer, context)
        assert chain == [issuer.get_certificate.return_value]

    def test_shared_secret_protection_rejects_unknown_algorithms(self) -> None:
        message = rfc4210.PKIMessage()
        context = Mock(cmp_shared_secret='secret', parsed_message=_message())
        pbm = rfc4210.PBMParameter()
        pbm['salt'] = b'salt'
        pbm['owf']['algorithm'] = '1.2.3.4'
        pbm['iterationCount'] = 1
        pbm['mac']['algorithm'] = HmacAlgorithm.HMAC_SHA256.dotted_string
        context.parsed_message['header']['protectionAlg']['parameters'] = der_encode(pbm)
        with pytest.raises(ValueError, match='owf algorithm not supported'):
            CmpMessageResponder._add_protection_shared_secret(message, context)


class TestCmpTypedMalformedBodies:
    def test_certconf_requires_hash_and_cert_req_id(self) -> None:
        body = PKIBody()
        body['certConf'].setComponentByPosition(0)
        status = body['certConf'][0]
        with pytest.raises(ValueError, match='certHash is REQUIRED'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)
        status['certHash'] = b'hash'
        with pytest.raises(ValueError, match='certReqId is REQUIRED'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)

    def test_certconf_rejects_invalid_status_and_hash_algorithm(self) -> None:
        body = PKIBody()
        body['certConf'].setComponentByPosition(0)
        status = body['certConf'][0]
        status['certHash'] = b'hash'
        status['certReqId'] = 0
        status['statusInfo']['status'] = 1
        with pytest.raises(ValueError, match='accepted'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)
        status['statusInfo'].clear()
        status['hashAlg']['algorithm'] = '1.2.3.4'
        with pytest.raises(ValueError, match='Unsupported certConf hashAlg'):
            CmpCertConfBodyValidation().parse_certconf_body(Mock(), body)

    def test_revocation_and_cert_request_cardinality_errors(self) -> None:
        body = rfc4210.PKIBody()
        body['rr'].setComponentByPosition(0)
        body['rr'].setComponentByPosition(1)
        with pytest.raises(ValueError, match='Multiple RevReqMessages'):
            CmpRevocationBodyValidation().parse_rr_body(Mock(), body)

        validator = CmpCertificateBodyValidation()
        with pytest.raises(ValueError, match='No CertReqMessages'):
            validator._validate_cert_req_messages([])
        with pytest.raises(ValueError, match='Multiple CertReqMessages'):
            validator._validate_cert_req_messages([Mock(), Mock()])

    def test_header_absent_implicit_confirm_and_body_operation_edges(self) -> None:
        message = _message()
        context = Mock(operation='initialization')
        CmpHeaderValidation()._check_implicit_confirm(context, message)
        assert context.implicit_confirm is False
        with pytest.raises(ValueError, match='Unsupported CMP operation'):
            CmpBodyValidation()._validate_operation_body_match('unknown', 'ir')
        with pytest.raises(ValueError, match='initialization or certification'):
            CmpBodyValidation()._validate_pollreq_operation('revocation')

    def test_rr_decodes_crl_reason_and_defaults_unknown_reason(self) -> None:
        body = rfc4210.PKIBody()
        body['rr'].setComponentByPosition(0)
        request = body['rr'][0]
        request['certDetails']['serialNumber'] = 0x10
        reason_extension = rfc2459.Extension()
        reason_extension['extnID'] = '2.5.29.21'
        reason_extension['extnValue'] = der_encode(rfc5280.CRLReason('keyCompromise'))
        request['crlEntryDetails'].append(reason_extension)
        context = Mock()
        CmpRevocationBodyValidation().parse_rr_body(context, body)
        assert context.revocation_reason is x509.ReasonFlags.unspecified

        reason_extension['extnID'] = '1.2.3.4'
        CmpRevocationBodyValidation().parse_rr_body(context, body)
        assert context.revocation_reason is x509.ReasonFlags.unspecified

    def test_pki_parser_rejects_malformed_intermediate_certificate(self, device_instance) -> None:
        parsed_message = _message()
        valid_cert, _ = der_decoder.decode(
            device_instance['cert'].public_bytes(Encoding.DER),
            asn1Spec=rfc4210.CMPCertificate(),
        )
        parsed_message['extraCerts'].append(valid_cert)
        parsed_message['extraCerts'].append(rfc4210.CMPCertificate())
        context = CmpBaseRequestContext(parsed_message=parsed_message)
        with pytest.raises(ValueError, match='Failed to extract CMP signer certificate'):
            CmpPkiMessageParsing()._extract_signer_certificate(context)

    def test_body_validation_dispatches_real_certconf_and_infers_operation(self) -> None:
        message = PKIMessage()
        message['header']['pvno'] = 2
        message['header']['transactionID'] = b't' * 16
        message['header']['senderNonce'] = b'n' * 16
        message['body']['certConf'].setComponentByPosition(0)
        status = message['body']['certConf'][0]
        status['certHash'] = b'hash'
        status['certReqId'] = 0
        context = CmpBaseRequestContext(parsed_message=message, operation=None)
        parsed_context = CmpBodyValidation().parse(context)
        assert isinstance(parsed_context, CmpCertConfRequestContext)
        assert parsed_context.operation == 'certconf'
        assert parsed_context.cert_conf_status == 0
