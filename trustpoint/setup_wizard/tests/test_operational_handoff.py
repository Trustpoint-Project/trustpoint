"""Tests for setup-wizard operational handoff payloads."""

from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_handoff import build_apply_payload


def test_build_apply_payload_includes_pkcs11_app_secret_policy() -> None:
    """The fresh-install payload carries the explicit PKCS#11 app-secret policy."""
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_enforce_app_secret_protection=True,
    )

    payload = build_apply_payload(config_model)

    assert payload['fresh_install']['pkcs11_enforce_app_secret_protection'] is True
