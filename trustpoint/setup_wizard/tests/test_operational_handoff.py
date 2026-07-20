"""Tests for setup-wizard operational handoff payloads."""

import pytest

from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.operational_handoff import build_apply_payload, build_operational_environment


def test_build_apply_payload_includes_pkcs11_app_secret_policy() -> None:
    """The fresh-install payload carries the explicit PKCS#11 app-secret policy."""
    config_model = SetupWizardConfigModel(
        crypto_storage=SetupWizardConfigModel.CryptoStorageType.HsmStorage,
        fresh_install_pkcs11_enforce_app_secret_protection=True,
    )

    payload = build_apply_payload(config_model)

    assert payload['fresh_install']['pkcs11_enforce_app_secret_protection'] is True


def test_build_operational_environment_preserves_local_softhsm_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local SoftHSM config paths are passed through instead of rewritten as uploaded configs."""
    softhsm_config_path = '/var/lib/trustpoint/hsm/config/softhsm2.conf'
    monkeypatch.setenv('TRUSTPOINT_LOCAL_HSM_SOFTHSM2_CONF', softhsm_config_path)

    config_model = SetupWizardConfigModel(
        operational_db_host='postgres',
        operational_db_port=5432,
        operational_db_name='trustpoint_db',
        operational_db_user='admin',
        operational_db_password='testing321',  # noqa: S106
        fresh_install_pkcs11_config_env_var='SOFTHSM2_CONF',
        fresh_install_pkcs11_config_path=softhsm_config_path,
    )

    env_values = build_operational_environment(config_model)

    assert env_values['SOFTHSM2_CONF'] == softhsm_config_path
