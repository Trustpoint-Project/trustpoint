"""Regression tests for manual no-onboarding device WebUI guidance."""

from unittest.mock import Mock, patch

import pytest
from django.http import Http404
from django.template.loader import render_to_string
from django.test import RequestFactory
from django.urls import resolve, reverse
from django.views.generic.detail import DetailView

from devices.views.credential_issuance import (
    DeviceNoOnboardingIssueNewApplicationCredentialView,
    OpcUaGdsNoOnboardingIssueNewApplicationCredentialView,
)
from help_pages.devices_help_views import (
    DeviceNoOnboardingCmpSharedSecretHelpView,
    DeviceNoOnboardingEstUsernamePasswordHelpView,
    DeviceNoOnboardingCmpWebUiHelpView,
    DeviceNoOnboardingEstWebUiHelpView,
    NoOnboardingCmpWebUiStrategy,
    NoOnboardingEstWebUiStrategy,
    OpcUaGdsNoOnboardingCmpWebUiHelpView,
    OpcUaGdsNoOnboardingEstWebUiHelpView,
)
from help_pages.help_section import HelpPage, ValueRenderType
from help_pages.tests.test_devices_help_views import _device, _domain as _base_domain, _help_context, _profile
from onboarding.models import NoOnboardingPkiProtocol


def _domain() -> Mock:
    domain = _base_domain()
    domain.issuing_ca = Mock(pk=77)
    domain.issuing_ca.credential.get_last_in_chain.return_value = Mock(pk=88)
    return domain


@pytest.mark.parametrize('view_class', [
    DeviceNoOnboardingIssueNewApplicationCredentialView,
    OpcUaGdsNoOnboardingIssueNewApplicationCredentialView,
])
@pytest.mark.parametrize('enabled_protocol', [
    NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD,
    NoOnboardingPkiProtocol.CMP_SHARED_SECRET,
    NoOnboardingPkiProtocol.MANUAL,
])
def test_webui_cards_follow_existing_protocol_flags(view_class, enabled_protocol) -> None:
    device = _device(_domain(), no_onboarding=True)
    device.no_onboarding_config.has_pki_protocol.side_effect = lambda protocol: protocol == enabled_protocol
    view = view_class()
    view.object = device
    view.request = RequestFactory().get('/')
    context = view.get_context_data()
    for label, protocol in [('EST', NoOnboardingPkiProtocol.EST_USERNAME_PASSWORD),
                            ('CMP', NoOnboardingPkiProtocol.CMP_SHARED_SECRET)]:
        cards = [section for section in context['sections'] if section.get('group') == label]
        assert len(cards) == 2
        assert str(cards[1]['heading']) == f'{label} with WebUI'
        assert all(card['enabled'] is (protocol == enabled_protocol) for card in cards)
        url = reverse(cards[1]['url'], kwargs={'pk': device.pk})
        html = render_to_string(view.template_name, context)
        assert f'{label} with WebUI' in html
        assert (f'href="{url}"' in html) is (protocol == enabled_protocol)
    assert any(section['protocol'] == 'manual' for section in context['sections'])
    assert any(section['protocol'] == 'rest-username-password' for section in context['sections'])


@pytest.mark.parametrize(('strategy_class', 'protocol', 'operation'), [
    (NoOnboardingEstWebUiStrategy, 'est', 'simpleenroll'),
    (NoOnboardingCmpWebUiStrategy, 'cmp', 'certification'),
])
def test_webui_profile_values_and_rendered_page(strategy_class, protocol, operation) -> None:
    domain = _domain()
    device = _device(domain, no_onboarding=True)
    device.no_onboarding_config.has_pki_protocol.return_value = True
    profiles = [_profile(alias='server-alias'), _profile('tls_client', 'TLS Client')]
    context = _help_context(device, domain, profiles)
    with patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.first',
               return_value=None):
        sections, heading = strategy_class().build_sections(context)
    profile_sections = [section for section in sections if section.css_id]
    assert [section.css_id for section in profile_sections] == ['server-alias', 'tls_client']
    assert [section.hidden for section in profile_sections] == [False, True]
    base = context.host_est_path if protocol == 'est' else context.host_cmp_path
    for section, title in zip(profile_sections, ['TLS Server', 'TLS Client'], strict=True):
        values = {row.key: row.value for row in section.rows[:5]}
        assert title in str(values['Certificate Profile'])
        assert values['Certificate Request URL'] == f'{base}/{section.css_id}/{operation}'
        assert values['Required Public Key Type'] == str(domain.public_key_info)
        authentication_keys = (
            ['EST Username', 'EST Password'] if protocol == 'est'
            else ['Key Identifier (KID)', 'CMP Shared Secret']
        )
        assert [row.key for row in section.rows][2:5] == ['Required Public Key Type', *authentication_keys]
        assert section.rows[0].key == 'Certificate Profile'
        assert f'value="{section.css_id}" selected' in str(section.rows[0].value)
        assert sum(row.key == 'Certificate Profile' for row in section.rows) == 1
        assert section.rows[5].key in ('Subject', 'Certificate Profile Requirements')
    assert not any(section.heading == 'Certificate Profile Selection' for section in sections)
    assert not any(section.heading in ('EST Authentication', 'CMP Authentication') for section in sections)
    rows = {row.key: row.value for section in sections for row in section.rows}
    if protocol == 'est':
        assert rows['EST Username'] == device.common_name
        assert rows['EST Password'] == device.no_onboarding_config.est_password
        assert any(section.heading == 'Download TLS Trust-Store' for section in sections)
    else:
        assert rows['Key Identifier (KID)'] == str(device.pk)
        assert rows['CMP Shared Secret'] == device.no_onboarding_config.cmp_shared_secret
        assert not any(section.heading == 'Download TLS Trust-Store' for section in sections)
    html = render_to_string('help/help_page.html', {
        'request': RequestFactory().get('/'),
        'help_page': HelpPage(heading=heading, sections=sections),
        'manual_webui': True,
        'ValueRenderType_CODE': ValueRenderType.CODE.value,
        'ValueRenderType_PLAIN': ValueRenderType.PLAIN.value,
        'ValueRenderType_HTML': ValueRenderType.HTML.value,
    })
    assert f'{base}/server-alias/{operation}' in html
    assert 'value="server-alias"' in html
    assert 'value="tls_client"' in html
    assert html.count('id="cert-profile-select-0"') == 1
    assert html.count('id="cert-profile-select-1"') == 1
    assert '<certificate_profile>' not in html
    assert 'OpenSSL' not in html
    assert 'curl' not in html
    assert 'showWindowsCommands"' not in html
    assert 'Adjust the parameters used to generate' not in html
    ca_url = reverse('pki:certificate-file-download-file-name', kwargs={
        'file_format': 'pem', 'pk': 88, 'file_name': 'ca-trust-store.pem',
    })
    assert 'Download CA Trust-Store' in html
    assert f'href="{ca_url}"' in html
    domain.issuing_ca.credential.get_last_in_chain.assert_called_once_with()


@pytest.mark.parametrize('strategy_class', [NoOnboardingEstWebUiStrategy, NoOnboardingCmpWebUiStrategy])
@pytest.mark.parametrize('no_onboarding', [False, True])
def test_webui_rejects_onboarding_or_disabled_protocol(strategy_class, no_onboarding) -> None:
    domain = _domain()
    device = _device(domain, no_onboarding=no_onboarding)
    if no_onboarding:
        device.no_onboarding_config.has_pki_protocol.return_value = False
    with pytest.raises(Http404):
        strategy_class().build_sections(_help_context(device, domain))


@pytest.mark.parametrize(('name', 'view_class'), [
    ('devices_no_onboarding_est_webui_help', DeviceNoOnboardingEstWebUiHelpView),
    ('devices_no_onboarding_cmp_webui_help', DeviceNoOnboardingCmpWebUiHelpView),
    ('opc_ua_gds_no_onboarding_est_webui_help', OpcUaGdsNoOnboardingEstWebUiHelpView),
    ('opc_ua_gds_no_onboarding_cmp_webui_help', OpcUaGdsNoOnboardingCmpWebUiHelpView),
])
def test_webui_routes_use_manual_help_views(name, view_class) -> None:
    url = reverse(f'devices:{name}', kwargs={'pk': 123})
    assert '/no-onboarding/issue-application-credential/' in url
    assert resolve(url).func.view_class is view_class
    assert view_class.manual_webui is True


def test_est_webui_reuses_existing_tls_trust_store_download() -> None:
    domain = _domain()
    device = _device(domain, no_onboarding=True)
    tls = Mock()
    tls.credential.get_last_in_chain.return_value = Mock(pk=42)
    with patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.first',
               return_value=tls):
        sections, _heading = NoOnboardingEstWebUiStrategy().build_sections(_help_context(device, domain))
    trust_store = sections[-1]
    assert trust_store.heading == 'Download TLS Trust-Store'
    expected_url = reverse('pki:certificate-file-download-file-name', kwargs={
        'file_format': 'pem', 'pk': 42, 'file_name': 'trustpoint-tls-trust-store.pem',
    })
    assert f'href="{expected_url}"' in trust_store.rows[0].value
    tls.credential.get_last_in_chain.assert_called_once_with()


@pytest.mark.parametrize(('view_class', 'manual_webui'), [
    (DeviceNoOnboardingEstWebUiHelpView, True),
    (DeviceNoOnboardingCmpWebUiHelpView, True),
    (DeviceNoOnboardingEstUsernamePasswordHelpView, False),
    (DeviceNoOnboardingCmpSharedSecretHelpView, False),
])
def test_help_context_limits_webui_flag_to_new_views(view_class, manual_webui) -> None:
    domain = _domain()
    view = view_class()
    view.object = _device(domain, no_onboarding=True)
    view.request = RequestFactory().get('/')
    view.request.user = Mock()
    with patch.object(DetailView, 'get_context_data', return_value={}), \
            patch.object(view, '_make_context', return_value=_help_context(view.object, domain)), \
            patch.object(view.strategy, 'build_sections', return_value=([], 'Help')), \
            patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.get'):
        context = view.get_context_data()
    assert context['manual_webui'] is manual_webui


@pytest.mark.parametrize('strategy_class', [NoOnboardingEstWebUiStrategy, NoOnboardingCmpWebUiStrategy])
def test_webui_shows_subject_and_san_profile_requirements(strategy_class) -> None:
    domain = _domain()
    device = _device(domain, no_onboarding=True)
    device.rfc_4122_uuid = 'device-uuid'
    profile = _profile()
    profile.certificate_profile.profile = {
        'type': 'cert_profile',
        'subj': {
            'common_name': {'required': True, 'mutable': True},
            'organization_name': {'default': '<Test Org>', 'mutable': True},
            'serial_number': {'value': '{{ device.rfc_4122_uuid }}', 'mutable': False},
        },
        'ext': {'subject_alternative_name': {
            'dns_names': {'required': True, 'mutable': True},
            'ip_addresses': {'default': ['192.0.2.1'], 'mutable': True},
        }},
        'validity': {'days': 30},
    }
    second_profile = _profile('tls_client', 'TLS Client')
    second_profile.certificate_profile.profile = {'type': 'cert_profile', 'subj': {}, 'validity': {'days': 30}}
    context = _help_context(device, domain, [profile, second_profile])
    with patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.first',
               return_value=None):
        sections, _heading = strategy_class().build_sections(context)
    profile_sections = [section for section in sections if section.css_id]
    rows = {row.key: str(row.value) for row in profile_sections[0].rows}
    subject = rows['Subject']
    san = rows['Subject Alternative Name (SAN)']
    assert 'Common Name' in subject
    assert 'Required' in subject
    assert 'Optional' in subject
    assert '&lt;Test Org&gt;' in subject
    assert 'Fixed by profile' in subject
    assert 'device-uuid' in subject
    assert 'DNS Names' in san
    assert 'Required' in san
    assert 'IP Addresses' in san
    assert '192.0.2.1' in san
    assert 'Days' not in subject + san
    assert profile_sections[1].hidden is True
    second_rows = {row.key: str(row.value) for row in profile_sections[1].rows}
    assert second_rows['Subject'] == 'No attributes specified by this profile.'
    assert second_rows['Subject Alternative Name (SAN)'] == 'No attributes specified by this profile.'


@pytest.mark.parametrize('strategy_class', [NoOnboardingEstWebUiStrategy, NoOnboardingCmpWebUiStrategy])
def test_webui_ca_trust_store_unavailable_without_issuing_ca(strategy_class) -> None:
    domain = _domain()
    domain.issuing_ca = None
    device = _device(domain, no_onboarding=True)
    with patch('help_pages.devices_help_views.ActiveTrustpointTlsServerCredentialModel.objects.first',
               return_value=None):
        sections, _heading = strategy_class().build_sections(_help_context(device, domain))
    section = next(section for section in sections if section.heading == 'Download CA Trust-Store')
    assert section.rows[0].value == 'No issuing CA is configured for this domain.'