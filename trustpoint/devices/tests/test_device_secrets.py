# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Policy, lifecycle and exact-input tests for device enrollment credentials."""

from cmp.models import CmpTransactionModel
from devices.serializers import DeviceSerializer
from django.contrib.auth.models import Permission
from django.core.management import call_command, CommandError
from django.urls import reverse
from io import StringIO
from pki.models.cert_profile import CertificateProfileModel
from pki.models.domain import DomainModel
from request.authentication.est import UsernamePasswordAuthentication
from request.authentication.rest import RestUsernamePasswordAuthentication
from request.request_context import BaseCertificateRequestContext
from request.request_context import EstBaseRequestContext, RestBaseRequestContext
from rest_framework.test import APIClient
from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone

from devices.forms import ChangeDeviceSecretForm, ClmDeviceModelOnboardingForm, NoOnboardingCreateForm
from devices.models import DeviceModel
from devices.secrets import assign_secret, remember_secret, secret_use
from devices.serializers import NoOnboardingConfigSerializer, OnboardingConfigSerializer, SecretReplacementSerializer
from management.models import SecurityConfig
from management.models.audit_log import AuditLog
from management.security_env import SecurityConfigurationError, synchronize_security_config
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol, OnboardingStatus
from onboarding.models import DeviceSecretUse, NoOnboardingConfigModel, OnboardingConfigModel
from request.request_context import BaseRequestContext

pytestmark = pytest.mark.django_db


@pytest.fixture
def policy():
    config = SecurityConfig.objects.create(pk=1, allow_user_defined_device_secrets=True)
    config.apply_security_settings()
    return config


def no_onboarding():
    config = NoOnboardingConfigModel(
        pki_protocols=1 | 4 | 32 | 64, cmp_shared_secret='generated-cmp', est_password='generated-est'
    )
    config.save()
    return config


@pytest.mark.parametrize('value', ['x', ' ', ' edge spaces ', 'a' * 128])
@pytest.mark.parametrize('field', ['cmp_shared_secret', 'est_password', 'scep_challenge'])
def test_custom_exact_printable_ascii(policy, value, field):
    config = no_onboarding()
    assert assign_secret(config, field, custom=True, value=value) == value
    config.refresh_from_db()
    assert getattr(config, field) == value
    assert not hasattr(config, 'credential_expires_at')
    audit = AuditLog.objects.filter(operation_type=AuditLog.OperationType.DEVICE_SECRET_CHANGED).latest('pk')
    assert audit.details == {'credential': field, 'action': 'custom', 'outcome': 'success'}


@pytest.mark.parametrize('value', ['', None, '\n', '\x00', '\x7f', 'ä', 'x' * 129])
def test_invalid_custom_is_atomic_and_redacted(policy, value):
    config = no_onboarding()
    before = config.est_password
    with pytest.raises(ValidationError):
        assign_secret(config, 'est_password', custom=True, value=value)
    config.refresh_from_db()
    assert config.est_password == before


def test_disabled_policy_preserves_value_and_allows_generated_replacement(policy):
    config = no_onboarding()
    assign_secret(config, 'est_password', custom=True, value='chosen')
    policy.allow_user_defined_device_secrets = False
    policy.save()
    with pytest.raises(ValidationError, match='disabled'):
        assign_secret(config, 'est_password', custom=True, value='replacement')
    config.refresh_from_db()
    assert config.est_password == 'chosen'
    assert assign_secret(config, 'est_password') != 'chosen'


def test_flag_and_ttl_conflict_at_model_and_database(policy):
    policy.credential_ttl_seconds = 60
    with pytest.raises(ValidationError):
        policy.save()
    with pytest.raises(IntegrityError), transaction.atomic():
        SecurityConfig.objects.filter(pk=policy.pk).update(credential_ttl_seconds=60)


def test_environment_preserves_choice_and_rejects_conflict(policy, monkeypatch):
    monkeypatch.setenv('TP_SECURITY_MODE', 'BROWNFIELD')
    monkeypatch.delenv('TP_SECURITY_ALLOW_USER_DEFINED_DEVICE_SECRETS', raising=False)
    monkeypatch.delenv('TP_SECURITY_CREDENTIAL_TTL_SECONDS', raising=False)
    assert synchronize_security_config()
    policy.refresh_from_db()
    assert policy.allow_user_defined_device_secrets
    monkeypatch.setenv('TP_SECURITY_CREDENTIAL_TTL_SECONDS', '60')
    with pytest.raises(SecurityConfigurationError):
        synchronize_security_config()
    policy.refresh_from_db()
    assert policy.credential_ttl_seconds is None


def test_scep_null_expiry_and_consumed_never_reopens(policy):
    config = no_onboarding()
    original = assign_secret(config, 'scep_challenge')
    assert config.scep_challenge_expires_at is None
    assert config.consume_scep_challenge()
    assert not config.consume_scep_challenge()
    for custom in (False, True):
        with pytest.raises(ValidationError, match='Consumed'):
            assign_secret(config, 'scep_challenge', custom=custom, value='other')
    config.refresh_from_db()
    assert config.scep_challenge == original
    assert config.scep_challenge_state() == 'consumed'


def test_scep_expired_unconsumed_replacement_uses_global_ttl():
    SecurityConfig.objects.create(pk=1, credential_ttl_seconds=120)
    config = no_onboarding()
    assign_secret(config, 'scep_challenge')
    original = config.scep_challenge
    NoOnboardingConfigModel.objects.filter(pk=config.pk).update(
        scep_challenge_expires_at=timezone.now() - timedelta(seconds=1),
    )
    assign_secret(config, 'scep_challenge')
    assert config.scep_challenge != original
    assert 115 < (config.scep_challenge_expires_at - timezone.now()).total_seconds() <= 120


def test_duplicate_scep_across_configuration_tables(policy):
    config = no_onboarding()
    assign_secret(config, 'scep_challenge', custom=True, value='unique-challenge')
    other = OnboardingConfigModel(onboarding_protocol=OnboardingProtocol.MANUAL)
    other.set_scep_challenge()
    other.scep_challenge = config.scep_challenge
    other.scep_challenge_digest = config.scep_challenge_digest
    with pytest.raises(ValidationError, match='already assigned'):
        other.save()


def test_superseded_authentication_and_pending_remote_operation(policy):
    config = no_onboarding()
    context = BaseRequestContext()
    remember_secret(context, config, 'est_password')
    with secret_use(context):
        assert DeviceSecretUse.objects.count() == 1
        with pytest.raises(ValidationError, match='operation'):
            assign_secret(config, 'est_password')
    assert not DeviceSecretUse.objects.exists()
    assign_secret(config, 'est_password')
    with pytest.raises(ValueError, match='changed'), secret_use(context):
        pytest.fail('Superseded authentication must not reach issuance')


def test_stale_model_cannot_restore_superseded_secret(policy):
    config = no_onboarding()
    stale = NoOnboardingConfigModel.objects.get(pk=config.pk)
    assign_secret(config, 'est_password')
    with pytest.raises(ValidationError, match='changed'):
        stale.save()


def test_completed_onboarding_cannot_restore_secrets_through_clm(policy):
    config = OnboardingConfigModel.objects.create(
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
        onboarding_status=OnboardingStatus.ONBOARDED,
    )
    device = DeviceModel.objects.create(common_name='completed-device', onboarding_config=config)
    form = ClmDeviceModelOnboardingForm(
        data={
            'common_name': device.common_name,
            'serial_number': '',
            'domain': '',
            'onboarding_status': 'Onboarded',
            'pki_protocol_est': True,
        },
        instance=device,
    )
    assert form.is_valid(), form.errors
    form.save(onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD)
    config.refresh_from_db()
    assert not config.est_password
    assert not ChangeDeviceSecretForm(device=device).available
    with pytest.raises(ValidationError, match='Completed'):
        assign_secret(config, 'est_password')


@pytest.mark.parametrize(
    'serializer_type,data',
    [
        (OnboardingConfigSerializer, {'onboarding_protocol': 4, 'est_password': 'chosen'}),
        (NoOnboardingConfigSerializer, {'pki_protocols': 4, 'est_password': 'chosen'}),
    ],
)
def test_api_custom_requires_flag(serializer_type, data):
    SecurityConfig.objects.create(pk=1)
    serializer = serializer_type(data=data)
    assert not serializer.is_valid()
    assert not OnboardingConfigModel.objects.exists()
    assert not NoOnboardingConfigModel.objects.exists()


def test_api_custom_exact_spaces_and_unrelated_patch(policy):
    serializer = OnboardingConfigSerializer(data={'onboarding_protocol': 4, 'est_password': ' exact '})
    assert serializer.is_valid(), serializer.errors
    config = serializer.save()
    assert config.est_password == ' exact '
    expiry = config.credential_expires_at
    update = OnboardingConfigSerializer(config, data={'pki_protocols': ['EST']}, partial=True)
    assert update.is_valid(), update.errors
    updated = update.save()
    assert updated.est_password == ' exact '
    assert updated.credential_expires_at == expiry


@pytest.mark.parametrize('override', [{'credential_ttl_seconds': 60}, {'credential_expires_at': None}])
def test_api_custom_expiry_override_rejected(policy, override):
    serializer = OnboardingConfigSerializer(data={'onboarding_protocol': 4, 'est_password': 'chosen', **override})
    assert not serializer.is_valid()


@pytest.mark.parametrize(
    'payload',
    [
        {'credential': 'est_password', 'action': 'custom'},
        {'credential': 'est_password', 'action': 'custom', 'value': ''},
        {'credential': 'est_password', 'action': 'custom', 'value': None},
        {'credential': 'est_password', 'action': 'generate', 'value': 'ignored'},
        {'credential': 'est_password', 'action': 'generate', 'credential_ttl_seconds': 60},
    ],
)
def test_explicit_replacement_contract(payload):
    assert not SecretReplacementSerializer(data=payload).is_valid()


def test_creation_form_rejects_forged_custom_when_hidden():
    SecurityConfig.objects.create(pk=1)
    form = NoOnboardingCreateForm(
        data={
            'common_name': 'forged',
            'no_onboarding_pki_protocols': ['4'],
            'est_password_action': 'custom',
            'est_password_value': 'chosen',
            'est_password_confirm': 'chosen',
        }
    )
    assert not form.is_valid()
    assert 'est_password_value' in form.errors


def test_creation_form_custom_and_default_generation(policy):
    custom = NoOnboardingCreateForm(
        data={
            'common_name': 'custom-form-device',
            'no_onboarding_pki_protocols': ['4', '32'],
            'est_password_action': 'custom',
            'est_password_value': ' exact ',
            'est_password_confirm': ' exact ',
        }
    )
    assert custom.is_valid(), custom.errors
    device = custom.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
    assert device.no_onboarding_config.est_password == ' exact '
    generated = NoOnboardingCreateForm(
        data={
            'common_name': 'generated-form-device',
            'no_onboarding_pki_protocols': ['1', '4', '64'],
        }
    )
    assert generated.is_valid(), generated.errors
    device = generated.save(device_type=DeviceModel.DeviceType.GENERIC_DEVICE)
    assert device.no_onboarding_config.est_password
    assert device.no_onboarding_config.cmp_shared_secret
    assert device.no_onboarding_config.scep_challenge_state() == 'active'


def test_management_api_replacement_and_permissions(policy, admin_user):

    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))

    config = no_onboarding()
    device = DeviceModel.objects.create(common_name='api-replace', no_onboarding_config=config)
    client = APIClient()
    endpoint = reverse('device-change-secret', args=[device.pk])
    assert client.post(endpoint, {'credential': 'est_password', 'action': 'generate'}).status_code == 401
    client.force_authenticate(user=admin_user)
    response = client.post(endpoint, {'credential': 'est_password', 'action': 'custom', 'value': ' exact '})
    assert response.status_code == 200, response.data
    config.refresh_from_db()
    assert config.est_password == response.data['value'] == ' exact '
    assert client.post(endpoint, {'credential': 'est_password', 'action': 'generate'}).status_code == 200
    config.refresh_from_db()
    assert config.est_password != ' exact '


def test_no_onboarding_api_expiry_override_nested_rejected(policy):

    serializer = DeviceSerializer(
        data={
            'common_name': 'nested-override',
            'no_onboarding_config': {'pki_protocols': 4, 'est_password': 'chosen', 'credential_expires_at': None},
        }
    )
    assert not serializer.is_valid()
    assert not DeviceModel.objects.exists()


def test_clm_links_to_separate_replacement_page(policy, admin_client, admin_user):

    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))
    config = no_onboarding()
    device = DeviceModel.objects.create(common_name='clm-replacement', no_onboarding_config=config)
    endpoint = f'/devices/certificate-lifecycle-management/{device.pk}/'
    response = admin_client.get(endpoint)
    assert response.status_code == 200
    assert b'Change device secret' in response.content
    change_endpoint = reverse('devices:devices_change_secret', kwargs={'pk': device.pk})
    assert f'href="{change_endpoint}"'.encode() in response.content
    assert b'data-secret-replacement' not in response.content
    response = admin_client.get(change_endpoint)
    assert response.status_code == 200
    assert b'data-secret-replacement' in response.content
    assert config.est_password.encode() not in response.content
    response = admin_client.post(
        change_endpoint,
        {
            'credential': 'est_password',
            'action': 'custom',
            'value': ' exact ',
            'confirmation': ' exact ',
        },
    )
    assert response.status_code == 302
    config.refresh_from_db()
    assert config.est_password == ' exact '
    assert response.url == endpoint


def test_secret_page_requires_manage_devices_permission(policy, admin_client, admin_user):
    admin_user.role.permissions.remove(Permission.objects.get(codename='manage_devices'))
    config = no_onboarding()
    device = DeviceModel.objects.create(common_name='unauthorized-replacement', no_onboarding_config=config)
    endpoint = reverse('devices:devices_change_secret', kwargs={'pk': device.pk})
    assert admin_client.get(endpoint).status_code == 403
    assert admin_client.post(endpoint, {'credential': 'est_password', 'action': 'generate'}).status_code == 403
    response = admin_client.get(reverse('devices:devices_certificate_lifecycle_management', kwargs={'pk': device.pk}))
    assert b'Change device secret' not in response.content
    config.refresh_from_db()
    assert config.est_password == 'generated-est'


def test_secret_page_displays_validation_errors(policy, admin_client, admin_user):
    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))
    config = no_onboarding()
    device = DeviceModel.objects.create(common_name='invalid-replacement', no_onboarding_config=config)
    endpoint = reverse('devices:devices_change_secret', kwargs={'pk': device.pk})
    response = admin_client.post(endpoint, {
        'credential': 'est_password', 'action': 'custom', 'value': 'chosen', 'confirmation': 'mismatch',
    })
    assert response.status_code == 200
    assert b'The secret and confirmation do not match.' in response.content
    assert b'data-secret-replacement' in response.content
    assert b'value="chosen"' not in response.content
    config.refresh_from_db()
    assert config.est_password == 'generated-est'


def test_secret_page_keeps_completed_onboarding_closed(policy, admin_client, admin_user):
    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))
    config = OnboardingConfigModel.objects.create(
        onboarding_protocol=OnboardingProtocol.CMP_SHARED_SECRET,
        onboarding_status=OnboardingStatus.ONBOARDED,
    )
    device = DeviceModel.objects.create(common_name='completed-replacement', onboarding_config=config)
    endpoint = reverse('devices:devices_change_secret', kwargs={'pk': device.pk})
    response = admin_client.get(endpoint)
    assert response.status_code == 200
    assert b'No enrollment secret is currently eligible' in response.content
    assert b'data-secret-replacement' not in response.content
    response = admin_client.post(endpoint, {'credential': 'cmp_shared_secret', 'action': 'generate'})
    assert response.status_code == 200
    config.refresh_from_db()
    assert not config.cmp_shared_secret


def test_reservation_released_after_failed_remote_operation(policy):
    config = no_onboarding()
    context = BaseRequestContext()
    remember_secret(context, config, 'est_password')
    with pytest.raises(RuntimeError), secret_use(context):
        raise RuntimeError('upstream failed')
    assert not DeviceSecretUse.objects.exists()
    assign_secret(config, 'est_password')


def test_confirm_pending_cmp_blocks_rotation_until_confirmation(policy):

    config = no_onboarding()
    device = DeviceModel.objects.create(common_name='cmp-pending', no_onboarding_config=config)
    tx = CmpTransactionModel.objects.create(
        device=device,
        transaction_id='pending-conf',
        operation='certification',
        request_body_type='cr',
        request_der=b'x',
        status='issued',
        implicit_confirm=False,
    )
    with pytest.raises(ValidationError, match='outstanding CMP'):
        assign_secret(config, 'cmp_shared_secret')
    tx.confirmed_at = timezone.now()
    tx.save()
    assign_secret(config, 'cmp_shared_secret')


def test_pending_onboarding_reservation_is_exclusive(policy):
    config = OnboardingConfigModel.objects.create(
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
        est_password='generated',
    )
    context = BaseRequestContext()
    remember_secret(context, config, 'est_password')
    reservation = DeviceSecretUse.objects.create(
        config_label=config._meta.label,
        config_pk=config.pk,
        credential='est_password',
    )
    with pytest.raises(ValueError, match='in progress'), secret_use(context):
        pytest.fail('Concurrent bootstrap issuance must not start')
    reservation.delete()
    with secret_use(context), secret_use(context):
        assert DeviceSecretUse.objects.count() == 1
    assert not DeviceSecretUse.objects.exists()


def test_duplicate_report_does_not_disclose_challenges_or_digests(policy):

    first = no_onboarding()
    second = no_onboarding()
    assign_secret(first, 'scep_challenge', custom=True, value='private chosen challenge')
    # Simulate pre-existing duplicate records that predate assignment validation.
    NoOnboardingConfigModel.objects.filter(pk=second.pk).update(
        scep_challenge_digest=first.scep_challenge_digest,
    )
    output = StringIO()
    with pytest.raises(CommandError):
        call_command('check_device_secret_duplicates', stdout=output)
    assert f'NoOnboardingConfigModel:{first.pk}' in output.getvalue()
    assert first.scep_challenge not in output.getvalue()
    assert first.scep_challenge_digest not in output.getvalue()
    with pytest.raises(ValidationError, match='Duplicate SCEP'):
        assign_secret(first, 'scep_challenge', custom=True, value='other chosen challenge')


@pytest.mark.parametrize(
    'serializer_type,data',
    [
        (OnboardingConfigSerializer, {'onboarding_protocol': 4, 'est_password': 123}),
        (NoOnboardingConfigSerializer, {'pki_protocols': 4, 'est_password': 123}),
        (SecretReplacementSerializer, {'credential': 'est_password', 'action': 'custom', 'value': 123}),
    ],
)
def test_custom_json_values_must_be_strings(policy, serializer_type, data):
    assert not serializer_type(data=data).is_valid()


def test_api_assignment_audits_target_the_device(policy, admin_user):

    admin_user.role.permissions.add(Permission.objects.get(codename='manage_devices'))
    client = APIClient()
    client.force_authenticate(user=admin_user)
    response = client.post(
        reverse('device-list'),
        {
            'common_name': 'device-audit',
            'no_onboarding_config': {'pki_protocols': 4, 'est_password': ' private '},
        },
        format='json',
    )
    assert response.status_code == 201, response.data
    audit = AuditLog.objects.filter(operation_type=AuditLog.OperationType.DEVICE_SECRET_CHANGED).latest('pk')
    assert audit.target == DeviceModel.objects.get(pk=response.data['id'])
    assert audit.actor == admin_user
    assert ' private ' not in str(audit.details)


def test_manual_completion_reserves_pending_bootstrap_credentials(policy):

    config = OnboardingConfigModel.objects.create(
        onboarding_protocol=OnboardingProtocol.EST_USERNAME_PASSWORD,
        est_password='bootstrap',
    )
    device = DeviceModel.objects.create(common_name='manual-completion', onboarding_config=config)
    context = BaseCertificateRequestContext(
        device=device,
        domain=DomainModel(unique_name='manual-domain'),
        certificate_profile_model=CertificateProfileModel(unique_name='domain_credential'),
    )
    with secret_use(context):
        assert DeviceSecretUse.objects.get().credential == 'onboarding'
        with pytest.raises(ValidationError, match='operation'):
            assign_secret(config, 'est_password')
        authenticated = BaseRequestContext()
        remember_secret(authenticated, config, 'est_password')
        with pytest.raises(ValueError, match='in progress'), secret_use(authenticated):
            pytest.fail('Bootstrap issuance must wait for manual completion')
    assert not DeviceSecretUse.objects.exists()


def test_shared_est_rest_custom_password_authentication_and_rotation(policy):

    config = no_onboarding()
    DeviceModel.objects.create(common_name='shared-password', no_onboarding_config=config)
    assign_secret(config, 'est_password', custom=True, value=' exact ')
    authenticators = [
        (
            UsernamePasswordAuthentication(),
            EstBaseRequestContext,
            {'est_username': 'shared-password', 'est_password': ' exact '},
        ),
        (
            RestUsernamePasswordAuthentication(),
            RestBaseRequestContext,
            {'rest_username': 'shared-password', 'rest_password': ' exact '},
        ),
    ]
    for authenticator, context_type, credentials in authenticators:
        context = context_type(**credentials)
        authenticator.authenticate(context)
        assert context.device.common_name == 'shared-password'
    assign_secret(config, 'est_password')
    for authenticator, context_type, credentials in authenticators:
        with pytest.raises(ValueError):
            authenticator.authenticate(context_type(**credentials))


def test_custom_assignment_obeys_existing_protocol_policy(policy):
    policy.permitted_no_onboarding_pki_protocols = [1]
    policy.save()
    config = no_onboarding()
    with pytest.raises(ValidationError, match='not permitted'):
        assign_secret(config, 'est_password', custom=True, value='chosen')
    assert config.est_password == 'generated-est'
