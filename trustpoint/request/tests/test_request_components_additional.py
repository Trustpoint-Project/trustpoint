"""Additional security and error-path tests for request components."""

from unittest.mock import MagicMock, Mock, patch

import pytest
from cryptography import x509
from cmp.models import CmpTransactionModel
from cmp.util import PKIFailureInfo, PKI_STATUS_REJECTION
from django.test import RequestFactory
from onboarding.models import OnboardingStatus
from pyasn1_modules import rfc4210
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type import tag, univ
from pyasn1_modules import rfc2459

from request.authentication.base import CompositeAuthentication
from request.authorization.base import (
    CompositeAuthorization,
    DomainScopeValidation,
    ProtocolAuthorization,
)
from request.cmp_transaction_state import CmpTransactionState
from request.message_parser.base import CompositeParsing, DomainParsing
from request.message_parser.cmp import (
    CmpBodyValidation,
    CmpCertificateBodyValidation,
    CmpCertConfBodyValidation,
    CmpHeaderValidation,
    CmpPkiMessageParsing,
    CmpPollReqBodyValidation,
    CmpRevocationBodyValidation,
)
from request.message_responder.cmp import (
    CmpCertificationResponder,
    CmpErrorMessageResponder,
    CmpRevocationResponder,
    CmpMessageResponder,
    CmpInitializationResponder,
    CmpPkiConfResponder,
    CmpTransactionResponder,
)
from request.operation_processor.cert_conf import CertConfProcessor
from request.operation_processor.general import OperationProcessor
from request.operation_processor.cmp_poll import CmpPollDisposition, CmpPollProcessor
from request.request_context import (
    BaseRequestContext,
    CmpCertConfRequestContext,
    CmpCertificateRequestContext,
    CmpBaseRequestContext,
    CmpPollRequestContext,
    CmpRevocationRequestContext,
    EstCertificateRequestContext,
    HttpBaseRequestContext,
)
from request.tests.test_est_client import certificate_and_csr
from workflows2.events.request_events import Events


class AuthComponent:
    def __init__(self, result: object = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls = 0

    def authenticate(self, context: BaseRequestContext) -> None:
        self.calls += 1
        if self.error:
            raise self.error
        if self.result is not None:
            context.device = self.result


class AuthorizationComponent:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls = 0

    def authorize(self, context: BaseRequestContext) -> None:
        self.calls += 1
        if self.error:
            raise self.error


class ParsingComponent:
    def __init__(self, result: BaseRequestContext | None = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls = 0

    def parse(self, context: BaseRequestContext) -> BaseRequestContext | None:
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


def test_composite_authentication_short_circuits_and_removes_components() -> None:
    device = Mock(common_name='device', ip_address=None)
    first = AuthComponent(error=ValueError('bad credentials'))
    second = AuthComponent(result=device)
    composite = CompositeAuthentication()
    composite.add(first)
    composite.add(second)
    request = RequestFactory().post('/')
    request.META['REMOTE_ADDR'] = '192.0.2.4'
    context = HttpBaseRequestContext(raw_message=request)

    composite.authenticate(context)

    assert context.device is device
    assert first.calls == 1 and second.calls == 1
    assert device.ip_address == '192.0.2.4'
    composite.remove(first)
    assert first not in composite.components
    with pytest.raises(ValueError, match='Authentication failed'):
        composite.remove(second)
        composite.authenticate(HttpBaseRequestContext())


def test_composite_authentication_reports_failure_and_sets_http_state() -> None:
    composite = CompositeAuthentication()
    composite.add(AuthComponent(error=RuntimeError('backend unavailable')))
    context = HttpBaseRequestContext()
    with pytest.raises(ValueError, match='All authentication methods'):
        composite.authenticate(context)
    assert context.http_response_status == 403
    assert context.http_response_content == 'Authentication failed.'


def test_composite_authorization_order_and_remove_errors() -> None:
    first = AuthorizationComponent()
    second = AuthorizationComponent()
    composite = CompositeAuthorization()
    composite.add(first)
    composite.add(second)
    context = BaseRequestContext(protocol='rest')
    composite.authorize(context)
    assert first.calls == 1 and second.calls == 1
    composite.remove(first)
    with pytest.raises(ValueError, match='non-existent'):
        composite.remove(first)


def test_composite_authorization_wraps_component_errors() -> None:
    composite = CompositeAuthorization()
    composite.add(AuthorizationComponent(error=ValueError('denied')))
    with pytest.raises(ValueError, match='AuthorizationComponent: denied'):
        composite.authorize(BaseRequestContext())


@pytest.mark.parametrize(
    ('protocol', 'expected'),
    [('est', None), (None, 'missing'), ('cmp', 'Unauthorized')],
)
def test_protocol_authorization_accepts_and_rejects(protocol: str | None, expected: str | None) -> None:
    component = ProtocolAuthorization(['est'])
    if expected is None:
        component.authorize(BaseRequestContext(protocol=protocol))
    else:
        with pytest.raises(ValueError, match=expected):
            component.authorize(BaseRequestContext(protocol=protocol))


def test_domain_scope_validation_checks_device_domain(domain_instance: dict[str, object]) -> None:
    domain = domain_instance['domain']
    device = Mock(domain=domain, common_name='device')
    component = DomainScopeValidation()
    component.authorize(BaseRequestContext(device=device, domain=domain))
    with pytest.raises(ValueError, match='Requested domain is missing'):
        component.authorize(BaseRequestContext(device=device))
    with pytest.raises(ValueError, match='Unauthorized requested domain'):
        component.authorize(BaseRequestContext(device=device, domain=Mock()))


def test_composite_parsing_updates_context_and_wraps_errors(domain_instance: dict[str, object]) -> None:
    domain = domain_instance['domain']
    replacement = EstCertificateRequestContext(domain=domain)
    first = ParsingComponent(result=replacement)
    second = ParsingComponent()
    composite = CompositeParsing()
    composite.add(first)
    composite.add(second)
    assert composite.parse(BaseRequestContext()) is replacement
    composite.remove(first)
    with pytest.raises(ValueError, match='non-existent'):
        composite.remove(first)
    failing = CompositeParsing()
    failing.add(ParsingComponent(error=ValueError('malformed')))
    with pytest.raises(ValueError, match='malformed'):
        failing.parse(BaseRequestContext())


def test_domain_parsing_handles_missing_special_and_unknown_domains(domain_instance: dict[str, object]) -> None:
    parser = DomainParsing()
    context = BaseRequestContext(domain_str=domain_instance['domain'].unique_name)
    parser.parse(context)
    assert context.domain == domain_instance['domain']
    parser.parse(BaseRequestContext())
    parser.parse(BaseRequestContext(domain_str='.aoki'))
    with pytest.raises(ValueError, match='does not exist'):
        parser.parse(BaseRequestContext(domain_str='unknown-domain'))


def test_certconf_acceptance_is_noop_and_rejection_without_credential_sets_error() -> None:
    processor = CertConfProcessor()
    processor.process_operation(CmpCertConfRequestContext(cert_conf_status=0))
    context = CmpCertConfRequestContext(cert_conf_status=PKI_STATUS_REJECTION)
    with pytest.raises(ValueError, match='credential_to_revoke'):
        processor.process_operation(context)
    assert context.http_response_status == 500
    assert context.error_code == PKIFailureInfo.SYSTEM_FAILURE


def test_certconf_rejection_delegates_to_revocation() -> None:
    context = CmpCertConfRequestContext(
        cert_conf_status=PKI_STATUS_REJECTION,
        credential_to_revoke=Mock(common_name='credential'),
    )
    with patch('request.operation_processor.cert_conf.CertificateRevocationProcessor.process_operation') as process:
        CertConfProcessor().process_operation(context)
    process.assert_called_once_with(context)
    with pytest.raises(TypeError, match='requires a CmpCertConfRequestContext'):
        CertConfProcessor().process_operation(BaseRequestContext())


def test_cmp_poll_disposition_covers_all_states() -> None:
    statuses = {
        CmpTransactionModel.Status.ISSUED: CmpPollDisposition.ISSUED,
        CmpTransactionModel.Status.PROCESSING: CmpPollDisposition.READY_FOR_FINAL_ISSUANCE,
        CmpTransactionModel.Status.WAITING: CmpPollDisposition.WAIT,
        CmpTransactionModel.Status.FAILED: CmpPollDisposition.TERMINAL,
    }
    for status, expected in statuses.items():
        record = Mock(status=status)
        assert CmpPollProcessor._determine_poll_disposition(record) == expected


def test_cmp_poll_requires_transaction_and_correct_context() -> None:
    processor = CmpPollProcessor()
    with pytest.raises(TypeError, match='requires a CmpPollRequestContext'):
        processor.process_operation(BaseRequestContext())
    with pytest.raises(ValueError, match='missing its CMP transaction'):
        processor.process_operation(CmpPollRequestContext())


def test_transaction_state_terminal_transitions_and_pending_details() -> None:
    transaction = CmpTransactionModel.objects.create(
        transaction_id='state-test', operation='initialization', request_body_type='ir',
        status=CmpTransactionModel.Status.WAITING,
    )
    rejected = CmpTransactionState.mark_terminal_from_run_status(
        transaction.pk, run_status='rejected'
    )
    assert rejected.status == CmpTransactionModel.Status.REJECTED
    assert rejected.backend == CmpTransactionModel.Backend.NONE
    assert CmpTransactionState._detail_for_pending_run_status('awaiting') == 'Enrollment request pending workflow approval.'
    assert CmpTransactionState._detail_for_pending_run_status('running') == 'Enrollment request pending workflow processing.'
    with pytest.raises(ValueError, match='requires a reject or fail'):
        CmpTransactionState.mark_terminal_from_request_decision(transaction.pk, request_decision=Mock())


def test_operation_processor_selects_processors_and_preserves_cmp_error() -> None:
    context = CmpCertificateRequestContext()
    with patch('request.operation_processor.general.CmpCertificateRequestProcessor.process_operation', side_effect=ValueError('invalid')):
        with pytest.raises(ValueError, match='invalid'):
            OperationProcessor().process_operation(context)
    assert context.http_response_status == 500
    assert context.error_details == 'PKI Operation processing failed.'
    with pytest.raises(TypeError, match='No suitable operation processor'):
        OperationProcessor().process_operation(BaseRequestContext())


@pytest.mark.parametrize(
    ('status', 'expected'),
    [
        (CmpTransactionModel.Status.WAITING, (3, 'pending')),
        (CmpTransactionModel.Status.PROCESSING, (3, 'Enrollment request pending workflow processing.')),
        (CmpTransactionModel.Status.REJECTED, (2, 'Enrollment request rejected.')),
        (CmpTransactionModel.Status.CANCELLED, (2, 'Enrollment request cancelled.')),
        (CmpTransactionModel.Status.FAILED, (2, 'Enrollment request failed.')),
        (CmpTransactionModel.Status.ISSUED, (2, 'Unsupported CMP transaction state: issued.')),
    ],
)
def test_transaction_responder_maps_transaction_states(status: str, expected: tuple[int, str]) -> None:
    record = Mock(status=status, detail='pending' if status == CmpTransactionModel.Status.WAITING else None)
    assert CmpTransactionResponder._detail_for_transaction_status(record) == expected


def test_transaction_responder_resolves_sender_kid_and_unknown_operations() -> None:
    empty_kid = CmpTransactionResponder._build_sender_kid(None)
    assert bytes(empty_kid) == b''
    context = CmpCertificateRequestContext(operation='unsupported', domain=None)
    assert CmpTransactionResponder._build_transaction_result_message(
        context=context, issued_cert=None, status=2, status_text='denied'
    ) is None
    assert CmpTransactionResponder.respond_if_needed(BaseRequestContext()) is False
    assert CmpTransactionResponder.respond_if_needed(CmpCertificateRequestContext()) is False


def test_cmp_responder_error_dispatch_sets_fallback_response() -> None:
    context = CmpBaseRequestContext(error_details='bad request', http_response_status=400)
    with patch.object(CmpErrorMessageResponder, '_build_response', side_effect=RuntimeError('cannot encode')):
        CmpMessageResponder.build_response(context)
    assert context.http_response_status == 400
    assert context.http_response_content == 'An error occurred processing the CMP request.'


def test_cmp_error_response_type_and_missing_context() -> None:
    assert CmpErrorMessageResponder._get_response_type_for_operation('initialization') == ('ip', 1)
    assert CmpErrorMessageResponder._get_response_type_for_operation('certification') == ('cp', 3)
    assert CmpErrorMessageResponder._get_response_type_for_operation('revocation') == ('rp', 12)
    assert CmpErrorMessageResponder._get_response_type_for_operation(None) == ('error', 23)
    with pytest.raises(TypeError, match='requires a CmpBaseRequestContext'):
        CmpErrorMessageResponder._build_response(BaseRequestContext())


def test_cmp_poll_response_builder_creates_pollrep_without_issuer() -> None:
    context = CmpPollRequestContext(
        parsed_message=Mock(), poll_cert_req_id=4, domain=None,
    )
    with patch.object(CmpTransactionResponder, '_build_response_message_header', return_value=rfc4210.PKIHeader()):
        response = CmpTransactionResponder._build_pollrep_message(
            context=context, detail='awaiting approval', check_after_seconds=9,
        )
    assert response['body'].getName() == 'pollRep'
    poll_content = response['body']['pollRep']
    assert int(poll_content[0]['certReqId']) == 4
    assert int(poll_content[0]['checkAfter']) == 9
    assert str(poll_content[0]['reason'][0]) == 'awaiting approval'


def test_cmp_header_validation_checks_version_lengths_and_implicit_confirm() -> None:
    validator = CmpHeaderValidation(transaction_id_length=2, sender_nonce_length=2)
    header = {
        'pvno': 2,
        'transactionID': Mock(asOctets=Mock(return_value=b'ab')),
        'senderNonce': Mock(asOctets=Mock(return_value=b'cd')),
    }
    message = MagicMock()
    message.__getitem__.side_effect = lambda key: {'header': header, 'body': Mock(getName=Mock(return_value='certConf'))}[key]
    validator._check_header(message)
    with pytest.raises(ValueError, match='pvno fail'):
        header['pvno'] = 9
        validator._check_header(message)
    header['pvno'] = 2
    header['transactionID'].asOctets.return_value = b'a'
    with pytest.raises(ValueError, match='transactionID fail'):
        validator._check_header(message)


def test_cmp_header_validation_tracks_implicit_confirm_and_skips_prohibited_bodies() -> None:
    validator = CmpHeaderValidation(transaction_id_length=2, sender_nonce_length=2)
    header = {
        'pvno': 2,
        'transactionID': Mock(asOctets=Mock(return_value=b'ab')),
        'senderNonce': Mock(asOctets=Mock(return_value=b'cd')),
        'generalInfo': [],
    }
    body = Mock(getName=Mock(return_value='ir'))
    message = MagicMock()
    message.__getitem__.side_effect = lambda key: {'header': header, 'body': body}[key]
    context = CmpBaseRequestContext(operation='initialization', parsed_message=message)

    validator.parse(context)

    assert context.cmp_transaction_id == '6162'
    assert context.implicit_confirm is False

    entry = MagicMock()
    info_type = Mock(prettyPrint=Mock(return_value=validator.implicit_confirm_oid))
    info_value = Mock(prettyPrint=Mock(return_value=validator.implicit_confirm_str_value))
    entry.__getitem__.side_effect = lambda key: {
        'infoType': info_type,
        'infoValue': info_value,
    }[key]
    header['generalInfo'] = [entry]
    validator.parse(context)
    assert context.implicit_confirm is True

    info_value.prettyPrint.return_value = 'wrong'
    with pytest.raises(ValueError, match='implicit confirm entry fail'):
        validator.parse(context)

    for body_name, operation in (('certConf', 'certification'), ('pollReq', 'initialization'), ('ir', 'other')):
        skipped = CmpBaseRequestContext(operation=operation, implicit_confirm=True)
        skipped_message = MagicMock()
        skipped_message.__getitem__.side_effect = lambda key, body_name=body_name: (
            {'body': Mock(getName=Mock(return_value=body_name)), 'header': header}[key]
        )
        validator._check_implicit_confirm(skipped, skipped_message)
        assert skipped.implicit_confirm is True


def test_cmp_pki_message_parsing_extracts_extra_certs_and_wraps_failures() -> None:
    _, certificate, _ = certificate_and_csr()
    parser = CmpPkiMessageParsing()
    context = CmpBaseRequestContext(parsed_message={'extraCerts': [Mock(), Mock()]})
    with patch('request.message_parser.cmp.der_encoder.encode', side_effect=[b'signer', b'intermediate']), \
         patch('request.message_parser.cmp.x509.load_der_x509_certificate', side_effect=[certificate, certificate]):
        parser._extract_signer_certificate(context)
    assert context.client_certificate is certificate
    assert context.client_intermediate_certificate == [certificate]

    with patch('request.message_parser.cmp.der_encoder.encode', side_effect=ValueError('bad cert')):
        with pytest.raises(ValueError, match='Failed to extract CMP signer certificate'):
            parser._extract_signer_certificate(CmpBaseRequestContext(parsed_message={'extraCerts': [Mock()]}))


def test_cmp_pki_message_parsing_rejects_wrong_and_malformed_raw_message() -> None:
    parser = CmpPkiMessageParsing()
    with pytest.raises(TypeError, match='requires a CmpBaseRequestContext'):
        parser.parse(BaseRequestContext())
    with pytest.raises(ValueError, match='Raw message is missing'):
        parser.parse(CmpBaseRequestContext())
    with pytest.raises(ValueError, match='Raw message is missing body'):
        parser.parse(CmpBaseRequestContext(raw_message=Mock(body=b'')))
    with patch('request.message_parser.cmp.ber_decoder.decode', side_effect=ValueError('broken')):
        with pytest.raises(ValueError, match='seems to be corrupted'):
            parser.parse(CmpBaseRequestContext(raw_message=Mock(body=b'broken')))


def test_cmp_certificate_body_validation_rejects_wrong_cardinality_and_request_id() -> None:
    validator = CmpCertificateBodyValidation()
    with pytest.raises(ValueError, match='No CertReqMessages'):
        validator._validate_cert_req_messages([])
    with pytest.raises(ValueError, match='Multiple CertReqMessages'):
        validator._validate_cert_req_messages([Mock(), Mock()])
    request = MagicMock()
    request.__getitem__.side_effect = lambda key: 1 if key == 'certReqId' else Mock(hasValue=Mock(return_value=False))
    with pytest.raises(ValueError, match='certReqId must be 0'):
        validator._validate_cert_request(request)
    request.__getitem__.side_effect = lambda key: 0 if key == 'certReqId' else Mock(hasValue=Mock(return_value=False))
    with pytest.raises(ValueError, match='certTemplate must be contained'):
        validator._validate_cert_request(request)
    template = MagicMock(hasValue=Mock(return_value=True))
    version = Mock(hasValue=Mock(return_value=True))
    version.__ne__ = Mock(return_value=True)
    template.__getitem__.return_value = version
    request.__getitem__.side_effect = lambda key: 0 if key == 'certReqId' else template
    with pytest.raises(ValueError, match='Version must be 2'):
        validator._validate_cert_request(request)


def test_cmp_certificate_body_parses_supported_extensions() -> None:
    validator = CmpCertificateBodyValidation()
    basic = rfc2459.BasicConstraints()
    basic['cA'] = True
    basic['pathLenConstraint'] = 1
    result = validator._parse_basic_constraints(der_encode(basic), critical=True)
    assert result.critical is True and result.value.ca is True and result.value.path_length == 1

    key_usage = rfc2459.KeyUsage('100000000')
    result = validator._parse_key_usage(der_encode(key_usage), critical=False)
    assert result.value.digital_signature is True

    eku = rfc2459.ExtKeyUsageSyntax()
    eku.append(univ.ObjectIdentifier('1.3.6.1.5.5.7.3.1'))
    result = validator._parse_extended_key_usage(der_encode(eku), critical=False)
    assert result.value[0].dotted_string == '1.3.6.1.5.5.7.3.1'

    ski = rfc2459.SubjectKeyIdentifier(b'0123456789abcdef')
    result = validator._parse_subject_key_identifier(der_encode(ski), critical=False)
    assert result.value.digest == b'0123456789abcdef'


def test_cmp_certificate_body_parses_general_names_and_rejects_unknown_extension() -> None:
    validator = CmpCertificateBodyValidation()
    san = rfc2459.SubjectAltName()
    name = rfc2459.GeneralName()
    name['dNSName'] = 'device.example.test'
    san.append(name)
    name = rfc2459.GeneralName()
    name['iPAddress'] = b'\xc0\x00\x02\x01'
    san.append(name)
    parsed = validator._parse_subject_alternative_name(der_encode(san), critical=False)
    assert parsed.value.get_values_for_type(__import__('cryptography').x509.DNSName) == ['device.example.test']
    assert str(parsed.value.get_values_for_type(__import__('cryptography').x509.IPAddress)[0]) == '192.0.2.1'

    extension = rfc2459.Extension()
    extension['extnID'] = '1.2.3.4'
    extension['extnValue'] = univ.OctetString(b'unsupported')
    extensions = rfc2459.Extensions()
    extensions.append(extension)
    with pytest.raises(NotImplementedError, match='not supported'):
        validator._parse_cert_template_extensions(extensions)


def test_cmp_body_validation_maps_and_rejects_operation_combinations() -> None:
    validator = CmpBodyValidation()
    assert validator._operation_from_body_type('ir') == 'initialization'
    assert validator._operation_from_body_type('cr') == 'certification'
    assert validator._operation_from_body_type('rr') == 'revocation'
    assert validator._operation_from_body_type('certConf') == 'certconf'
    for body_type in ('unknown', 'pollReq'):
        with pytest.raises(ValueError):
            validator._operation_from_body_type(body_type)
    validator._validate_operation_body_match('initialization', 'certConf')
    validator._validate_operation_body_match('certification', 'certConf')
    with pytest.raises(ValueError, match='Expected CMP rr body'):
        validator._validate_operation_body_match('revocation', 'cr')
    with pytest.raises(ValueError, match='Unsupported CMP operation'):
        validator._validate_operation_body_match('other', 'cr')
    validator._validate_pollreq_operation(None)
    validator._validate_pollreq_operation('initialization')
    with pytest.raises(ValueError, match='initialization or certification'):
        validator._validate_pollreq_operation('revocation')


def test_cmp_body_validators_cover_empty_and_invalid_requests() -> None:
    rr_validator = CmpRevocationBodyValidation()
    body = MagicMock()
    body.__getitem__.return_value = []
    with pytest.raises(ValueError, match='No RevReqMessages'):
        rr_validator.parse_rr_body(Mock(), body)

    certconf_validator = CmpCertConfBodyValidation()
    body = MagicMock()
    body.__getitem__.return_value = []
    with pytest.raises(ValueError, match='exactly one CertStatus'):
        certconf_validator._extract_single_cert_status(body)
    poll_validator = CmpPollReqBodyValidation()
    body.__getitem__.return_value = [Mock()]
    poll_entry = MagicMock()
    poll_entry.__getitem__.return_value = 1
    body.__getitem__.return_value = [poll_entry]
    with pytest.raises(ValueError, match='certReqId MUST be 0'):
        poll_validator.parse_pollreq_body(Mock(), body)

    body.__getitem__.return_value = []
    with pytest.raises(ValueError, match='exactly one CertReq reference'):
        poll_validator.parse_pollreq_body(Mock(), body)
    body.__getitem__.return_value = [Mock(), Mock()]
    with pytest.raises(ValueError, match='exactly one CertReq reference'):
        poll_validator.parse_pollreq_body(Mock(), body)


def test_cmp_revocation_body_validation_rejects_missing_details_and_parses_reason() -> None:
    validator = CmpRevocationBodyValidation()
    request = MagicMock()
    request.__getitem__.side_effect = lambda key: Mock(hasValue=Mock(return_value=False))
    body = MagicMock()
    body.__getitem__.return_value = [request]
    with pytest.raises(ValueError, match='certDetails must be contained'):
        validator.parse_rr_body(CmpRevocationRequestContext(), body)

    details = MagicMock()
    details.__getitem__.side_effect = lambda key: Mock(hasValue=Mock(return_value=False))
    request.__getitem__.side_effect = lambda key: details if key == 'certDetails' else Mock(hasValue=Mock(return_value=False))
    with pytest.raises(ValueError, match='serialNumber must be present'):
        validator.parse_rr_body(CmpRevocationRequestContext(), body)

    serial = Mock(hasValue=Mock(return_value=True))
    serial.__int__ = Mock(return_value=15)
    reason_extension = MagicMock()
    reason_extension.__getitem__.side_effect = lambda key: {
        'extnID': '2.5.29.21',
        'extnValue': Mock(asOctets=Mock(return_value=b'reason')),
    }[key]
    crl_details = MagicMock(hasValue=Mock(return_value=True))
    crl_details.__getitem__.return_value = reason_extension
    details.__getitem__.side_effect = lambda key: serial if key == 'serialNumber' else Mock(hasValue=Mock(return_value=True))
    request.__getitem__.side_effect = lambda key: (
        details if key == 'certDetails' else crl_details
    )
    with patch('request.message_parser.cmp.der_decoder.decode', side_effect=ValueError('bad reason')):
        with pytest.raises(ValueError, match='bad reason'):
            validator.parse_rr_body(CmpRevocationRequestContext(), body)


def test_cmp_certconf_validation_rejects_missing_fields_and_hash_algorithm() -> None:
    validator = CmpCertConfBodyValidation()
    status = MagicMock()
    hash_alg = MagicMock()
    status.__getitem__.side_effect = lambda key: {
        'certHash': univ.OctetString(b'hash'),
        'certReqId': univ.Integer(0),
        'statusInfo': Mock(hasValue=Mock(return_value=False)),
        'hashAlg': hash_alg,
    }[key]
    hash_alg.hasValue.return_value = True
    hash_alg.__getitem__.return_value = Mock(prettyPrint=Mock(return_value='1.2.3.4'))
    body = MagicMock()
    body.__getitem__.return_value = [status]
    with pytest.raises(ValueError, match='Unsupported certConf hashAlg OID'):
        validator.parse_certconf_body(CmpCertConfRequestContext(), body)

    hash_alg.__getitem__.return_value = Mock(
        prettyPrint=Mock(return_value='1.3.14.3.2.26')
    )
    with pytest.raises(ValueError, match='not permitted'):
        validator.parse_certconf_body(CmpCertConfRequestContext(), body)

    missing_id = MagicMock()
    missing_id.__getitem__.side_effect = lambda key: {
        'certHash': univ.OctetString(b'hash'),
        'certReqId': Mock(hasValue=Mock(return_value=False)),
    }[key]
    body.__getitem__.return_value = [missing_id]
    with pytest.raises(ValueError, match='certReqId is REQUIRED'):
        validator.parse_certconf_body(CmpCertConfRequestContext(), body)


def test_cmp_body_validation_dispatches_real_typed_body_and_rejects_mismatch() -> None:
    message = rfc4210.PKIMessage()
    message['body']['certConf'][0]['certHash'] = b'hash'
    message['body']['certConf'][0]['certReqId'] = 0
    with patch.object(CmpCertConfBodyValidation, '_parse_cert_hash_algorithm_oid', return_value=None):
        result = CmpBodyValidation().parse(
            CmpBaseRequestContext(operation='certconf', parsed_message=message)
        )
    assert isinstance(result, CmpCertConfRequestContext)
    assert result.cmp_body_type == 'certConf'
    assert result.cert_hash == b'hash'
    assert result.event == Events.cmp_certconf

    wrong = rfc4210.PKIMessage()
    wrong['body']['rr']
    with pytest.raises(ValueError, match='Expected CMP certConf body'):
        CmpBodyValidation().parse(
            CmpBaseRequestContext(operation='certconf', parsed_message=wrong)
        )


def test_cmp_response_header_and_implicit_confirm_are_typed() -> None:
    _, certificate, _ = certificate_and_csr()
    incoming = rfc4210.PKIMessage()
    incoming['header']['pvno'] = 2
    incoming['header']['transactionID'] = b'ab'
    incoming['header']['senderNonce'] = b'cd'
    header = CmpMessageResponder._build_response_message_header(
        incoming, rfc2459.KeyIdentifier(b'kid').subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ), certificate,
    )
    assert int(header['pvno']) == 2
    assert bytes(header['transactionID']) == b'ab'
    assert bytes(header['recipNonce']) == b'cd'
    message = rfc4210.PKIMessage()
    message['header'] = header
    message['body'] = rfc4210.PKIBody()
    CmpMessageResponder._grant_implicit_confirm(message)
    assert len(message['header']['generalInfo']) == 1
    assert message['header']['generalInfo'][0]['infoType'].prettyPrint() == '1.3.6.1.5.5.7.4.13'


def test_cmp_response_builders_assemble_real_certificate_messages() -> None:
    key, certificate, _ = certificate_and_csr()
    credential = Mock(pk=1)
    credential.get_certificate.return_value = certificate
    credential.get_certificate_chain.return_value = []
    parsed_message = MagicMock()
    parsed_message.__getitem__.side_effect = lambda name: {
        'header': {'sender': rfc4210.PKIHeader()['sender'], 'transactionID': univ.OctetString(b'ab'),
                   'senderNonce': univ.OctetString(b'cd'), 'protectionAlg': rfc4210.PKIHeader()['protectionAlg'],
                   'generalInfo': rfc4210.PKIHeader()['generalInfo']},
    }[name]
    header = rfc4210.PKIHeader()
    sender_kid = rfc2459.KeyIdentifier(b'kid')
    with patch.object(CmpMessageResponder, '_build_response_message_header', return_value=header):
        ip = CmpInitializationResponder._build_base_ip_message(
            parsed_message, certificate, credential, sender_kid, context=None,
        )
        cp = CmpCertificationResponder._build_base_cp_message(
            parsed_message, certificate, credential, sender_kid, context=None,
        )
        rp = CmpRevocationResponder._build_base_rp_message(parsed_message, credential, sender_kid)
    assert ip['body'].getName() == 'ip' and len(ip['extraCerts']) == 1
    assert cp['body'].getName() == 'cp' and len(cp['extraCerts']) == 1
    assert rp['body'].getName() == 'rp' and len(rp['extraCerts']) == 1


def _cmp_message() -> rfc4210.PKIMessage:
    message = rfc4210.PKIMessage()
    message['header']['pvno'] = 2
    message['header']['sender']['dNSName'] = 'device.example.test'
    message['header']['transactionID'] = b'transaction'
    message['header']['senderNonce'] = b'nonce'
    return message


@pytest.mark.django_db
def test_cmp_message_responder_dispatches_typed_responses_and_fallback() -> None:
    _, certificate, _ = certificate_and_csr()
    credential = Mock(pk=1)
    credential.get_certificate.return_value = certificate
    credential.get_certificate_chain.return_value = []
    cases = [
        (CmpCertificateRequestContext(operation='initialization', issued_certificate=certificate), 'ip'),
        (CmpCertificateRequestContext(operation='certification', issued_certificate=certificate), 'cp'),
        (CmpRevocationRequestContext(operation='revocation'), 'rp'),
        (CmpCertConfRequestContext(), 'pkiconf'),
    ]
    for context, body_name in cases:
        context.parsed_message = _cmp_message()
        context.issuer_credential = credential
        with patch.object(CmpMessageResponder, '_sign_pki_message', side_effect=lambda pki_message, context: pki_message):
            CmpMessageResponder.build_response(context)
        from pyasn1.codec.der.decoder import decode
        response, _ = decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
        assert response['body'].getName() == body_name
        assert context.http_response_status == 200
        assert context.http_response_content_type == 'application/pkixcmp'

    unsupported = CmpBaseRequestContext(operation='unknown', parsed_message=_cmp_message())
    with patch.object(CmpErrorMessageResponder, '_build_response', side_effect=RuntimeError('encode')):
        CmpMessageResponder.build_response(unsupported)
    assert unsupported.http_response_status == 500
    assert unsupported.http_response_content == 'No suitable responder found for this CMP message.'


@pytest.mark.parametrize(
    ('responder', 'context', 'message'),
    [
        (CmpInitializationResponder, BaseRequestContext(), 'CmpInitializationResponder requires'),
        (CmpCertificationResponder, BaseRequestContext(), 'CmpCertificationResponder requires'),
        (CmpRevocationResponder, BaseRequestContext(), 'CmpRevocationResponder requires'),
        (CmpPkiConfResponder, BaseRequestContext(), 'CmpPkiConfResponder requires'),
    ],
)
def test_cmp_responders_reject_wrong_context(responder: type[object], context: BaseRequestContext, message: str) -> None:
    with pytest.raises(TypeError, match=message):
        responder.build_response(context)  # type: ignore[attr-defined]


def test_cmp_certificate_responders_validate_missing_fields() -> None:
    context = CmpCertificateRequestContext()
    with pytest.raises(ValueError, match='Issued certificate'):
        CmpInitializationResponder.build_response(context)
    context.issued_certificate = certificate_and_csr()[1]
    with pytest.raises(ValueError, match='Issuer credential'):
        CmpCertificationResponder.build_response(context)


@pytest.mark.django_db
def test_cmp_initialization_owner_and_implicit_confirm_onboard_device(
    device_instance_onboarding: dict[str, object],
) -> None:
    device = device_instance_onboarding['device']
    certificate = device_instance_onboarding['cert']
    issuer = Mock(pk=1, get_certificate=Mock(return_value=certificate), get_certificate_chain=Mock(return_value=[]))
    owner = Mock(pk=2, get_certificate=Mock(return_value=certificate), get_certificate_chain=Mock(return_value=[]))
    context = CmpCertificateRequestContext(
        parsed_message=_cmp_message(), issued_certificate=certificate, issuer_credential=issuer,
        owner_credential=owner, implicit_confirm=True, device=device,
    )
    with patch.object(CmpMessageResponder, '_sign_pki_message', side_effect=lambda pki_message, context: pki_message):
        CmpInitializationResponder.build_response(context)
    from pyasn1.codec.der.decoder import decode
    response, _ = decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
    assert response['body'].getName() == 'ip'
    assert response['header']['generalInfo'][0]['infoType'].prettyPrint() == '1.3.6.1.5.5.7.4.13'
    assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED


def test_cmp_revocation_requires_issuer_credential() -> None:
    with pytest.raises(ValueError, match='Issuer credential'):
        CmpRevocationResponder.build_response(CmpRevocationRequestContext(parsed_message=_cmp_message()))


def test_cmp_pki_conf_credential_resolution_errors() -> None:
    context = CmpCertConfRequestContext(parsed_message=_cmp_message())
    with pytest.raises(ValueError, match='Cannot determine issuing CA credential'):
        CmpPkiConfResponder.build_response(context)
    context.domain = Mock(issuing_ca=Mock(get_credential=Mock(return_value=None)))
    with pytest.raises(ValueError, match='has no credential'):
        CmpPkiConfResponder.build_response(context)


def test_cmp_pki_conf_acceptance_onboards_and_builds_null_body() -> None:
    _, certificate, _ = certificate_and_csr()
    device = Mock(onboarding_config=Mock())
    credential = Mock(get_certificate=Mock(return_value=certificate))
    context = CmpCertConfRequestContext(
        parsed_message=_cmp_message(), issuer_credential=credential, device=device, cert_conf_status=0,
    )
    with patch.object(CmpMessageResponder, '_sign_pki_message', side_effect=lambda pki_message, context: pki_message):
        CmpPkiConfResponder.build_response(context)
    from pyasn1.codec.der.decoder import decode
    response, _ = decode(context.http_response_content, asn1Spec=rfc4210.PKIMessage())
    assert response['body'].getName() == 'pkiconf'
    assert device.onboarding_config.onboarding_status == OnboardingStatus.ONBOARDED
    device.onboarding_config.save.assert_called_once()


def test_cmp_error_base_contains_rejection_and_fail_info() -> None:
    context = CmpBaseRequestContext(
        parsed_message=_cmp_message(), error_details='bad request', error_code=PKIFailureInfo.SYSTEM_FAILURE,
    )
    response = CmpErrorMessageResponder._build_base_err_message(
        context.parsed_message,
        None,
        rfc2459.KeyIdentifier(b'').subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        ),
        context,
    )
    status = response['body']['error']['pKIStatusInfo']
    assert response['body'].getName() == 'error'
    assert int(status['status']) == 2
    assert str(status['statusString'][0]) == 'bad request'
    assert status['failInfo'].isValue


@pytest.mark.parametrize('operation', ['initialization', 'certification'])
def test_cmp_transaction_result_message_selects_operation_builder(operation: str) -> None:
    context = CmpCertificateRequestContext(operation=operation, parsed_message=_cmp_message())
    issuer = Mock()
    with patch.object(CmpTransactionResponder, '_resolve_issuer_credential', return_value=issuer), \
            patch.object(CmpTransactionResponder, '_build_sender_kid', return_value=Mock()), \
            patch.object(CmpInitializationResponder, '_build_base_ip_message', return_value='ip') as ip_builder, \
            patch.object(CmpCertificationResponder, '_build_base_cp_message', return_value='cp') as cp_builder:
        result = CmpTransactionResponder._build_transaction_result_message(
            context=context, issued_cert=None, status=2, status_text='failed',
        )
    assert result == ('ip' if operation == 'initialization' else 'cp')
    (ip_builder if operation == 'initialization' else cp_builder).assert_called_once()


def test_cmp_transaction_protection_selects_shared_secret_or_signature() -> None:
    message = rfc4210.PKIMessage()
    shared = CmpCertificateRequestContext(cmp_shared_secret='secret')
    signed = CmpCertificateRequestContext()
    with patch.object(CmpTransactionResponder, '_add_protection_shared_secret', return_value='mac') as mac, \
            patch.object(CmpTransactionResponder, '_sign_pki_message', return_value='signature') as signature:
        assert CmpTransactionResponder._protect_pki_message(message, context=shared) == 'mac'
        assert CmpTransactionResponder._protect_pki_message(message, context=signed) == 'signature'
    mac.assert_called_once()
    signature.assert_called_once()
