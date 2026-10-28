# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""EST setup helpers retain each command's resource names and reuse existing resources."""

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from aoki.management.commands.aoki_setup_est_onboarding_test_env import Command as OnboardingCommand
from aoki.management.commands.aoki_setup_est_test_env import Command as NoOnboardingCommand
from pki.models import CaModel
from pki.models.truststore import TruststoreModel, TruststoreOrderModel


@pytest.mark.parametrize('command_class', [NoOnboardingCommand, OnboardingCommand])
def test_est_infrastructure_uses_command_configuration_and_reuses_resources(
    command_class, issuing_ca_instance, tmp_path
):
    """CA, domain, and TLS truststore creation use the selected command's configuration."""
    command = command_class()
    command.https_server_cert_path = tmp_path / 'https.pem'
    command.https_server_cert_path.write_bytes(issuing_ca_instance['cert'].public_bytes(Encoding.PEM))

    issuing_ca = command._get_or_create_issuing_ca()
    domain = command._get_or_create_domain(issuing_ca)
    truststore = command._get_or_create_tls_truststore()

    assert issuing_ca.unique_name == command.ca_unique_name
    assert domain.unique_name == command.domain_unique_name
    assert domain.issuing_ca_id == issuing_ca.pk
    assert truststore.unique_name == command.truststore_unique_name
    assert truststore.intended_usage == TruststoreModel.IntendedUsage.TLS
    assert TruststoreOrderModel.objects.filter(trust_store=truststore).count() == 1

    # Reusing the truststore must not read the input certificate again.
    command.https_server_cert_path.unlink()
    assert command._get_or_create_issuing_ca().pk == issuing_ca.pk
    assert command._get_or_create_domain(issuing_ca).pk == domain.pk
    assert command._get_or_create_tls_truststore().pk == truststore.pk
    assert CaModel.objects.filter(unique_name=command.ca_unique_name).count() == 1
