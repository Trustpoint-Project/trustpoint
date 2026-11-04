# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""EST setup helpers retain each command's resource names and reuse existing resources."""

import pytest
from django.core.management.base import CommandError

from aoki.management.commands.aoki_setup_est_onboarding_test_env import Command as OnboardingCommand
from aoki.management.commands.aoki_setup_est_test_env import Command as NoOnboardingCommand
from pki.models import CaModel
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel, TruststoreModel, TruststoreOrderModel


@pytest.mark.parametrize('command_class', [NoOnboardingCommand, OnboardingCommand])
def test_est_infrastructure_uses_command_configuration_and_reuses_resources(
    command_class, issuing_ca_instance, credential_instance
):
    """CA, domain, and TLS truststore creation use the selected command's configuration."""
    command = command_class()
    active = ActiveTrustpointTlsServerCredentialModel.objects.create(credential=credential_instance['credential'])

    issuing_ca = command._get_or_create_issuing_ca()
    domain = command._get_or_create_domain(issuing_ca)
    truststore = command._get_or_create_tls_truststore()

    assert issuing_ca.unique_name == command.ca_unique_name
    assert domain.unique_name == command.domain_unique_name
    assert domain.issuing_ca_id == issuing_ca.pk
    assert truststore.unique_name == command.truststore_unique_name
    assert truststore.intended_usage == TruststoreModel.IntendedUsage.TLS
    assert TruststoreOrderModel.objects.filter(trust_store=truststore).count() == 1

    assert truststore.certificates.get() == active.credential.certificate
    active.credential = issuing_ca_instance['issuing_ca'].credential
    active.save()
    assert command._get_or_create_issuing_ca().pk == issuing_ca.pk
    assert command._get_or_create_domain(issuing_ca).pk == domain.pk
    assert command._get_or_create_tls_truststore().pk == truststore.pk
    assert CaModel.objects.filter(unique_name=command.ca_unique_name).count() == 1
    assert truststore.certificates.get() == active.credential.certificate


@pytest.mark.parametrize('command_class', [NoOnboardingCommand, OnboardingCommand])
def test_tls_truststore_requires_active_certificate(command_class):
    ActiveTrustpointTlsServerCredentialModel.objects.all().delete()
    with pytest.raises(CommandError, match='No active HTTPS server certificate'):
        command_class()._get_or_create_tls_truststore()
    assert not TruststoreModel.objects.filter(unique_name=command_class.truststore_unique_name).exists()
