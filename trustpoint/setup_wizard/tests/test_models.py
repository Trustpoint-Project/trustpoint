"""Tests for setup_wizard.models module."""

from __future__ import annotations

import pytest
from django.core.exceptions import ValidationError

from setup_wizard.models import (
    SetupWizardCompletedModel,
    SetupWizardConfigModel,
    default_tls_dns_names,
    default_tls_ipv4_addresses,
    default_tls_ipv6_addresses,
)


# ---------------------------------------------------------------------------
# Default value helpers
# ---------------------------------------------------------------------------


class TestDefaultHelpers:
    """Tests for the module-level SAN default functions."""

    def test_default_tls_ipv4_addresses(self) -> None:
        """Returns a list containing only 127.0.0.1."""
        assert default_tls_ipv4_addresses() == ['127.0.0.1']

    def test_default_tls_ipv6_addresses(self) -> None:
        """Returns a list containing only the loopback IPv6 address."""
        assert default_tls_ipv6_addresses() == ['::1']

    def test_default_tls_dns_names(self) -> None:
        """Returns a list containing only localhost."""
        assert default_tls_dns_names() == ['localhost']

    def test_defaults_return_new_list_each_call(self) -> None:
        """Each call returns a distinct list object to avoid shared-state bugs."""
        assert default_tls_ipv4_addresses() is not default_tls_ipv4_addresses()
        assert default_tls_ipv6_addresses() is not default_tls_ipv6_addresses()
        assert default_tls_dns_names() is not default_tls_dns_names()


# ---------------------------------------------------------------------------
# SetupWizardCompletedModel
# ---------------------------------------------------------------------------


class TestSetupWizardCompletedModelStr:
    """Tests for SetupWizardCompletedModel.__str__."""

    def test_str_when_pending(self) -> None:
        """Returns 'setup=pending' representation when not completed."""
        instance = SetupWizardCompletedModel()
        assert str(instance) == 'SetupWizardCompletedModel(setup=pending)'

    def test_str_when_completed(self) -> None:
        """Returns timestamped representation once setup_completed_at is set."""
        import datetime

        ts = datetime.datetime(2025, 6, 1, 10, 30, 0, tzinfo=datetime.UTC)
        instance = SetupWizardCompletedModel(setup_completed_at=ts)
        result = str(instance)
        assert result.startswith('SetupWizardCompletedModel(setup=completed at ')
        assert '2025-06-01' in result


class TestSetupWizardCompletedModelClassMethod:
    """Tests for SetupWizardCompletedModel.setup_wizard_completed class method."""

    @pytest.mark.django_db
    def test_returns_false_when_no_row(self) -> None:
        """Returns False when the singleton row does not exist."""
        assert SetupWizardCompletedModel.setup_wizard_completed() is False

    @pytest.mark.django_db
    def test_returns_false_when_timestamp_is_null(self) -> None:
        """Returns False when the row exists but setup_completed_at is None."""
        SetupWizardCompletedModel.objects.create(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
            setup_completed_at=None,
        )
        assert SetupWizardCompletedModel.setup_wizard_completed() is False

    @pytest.mark.django_db
    def test_returns_true_when_timestamp_is_set(self) -> None:
        """Returns True when setup_completed_at is non-null."""
        import datetime

        SetupWizardCompletedModel.objects.create(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
            setup_completed_at=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        )
        assert SetupWizardCompletedModel.setup_wizard_completed() is True


class TestSetupWizardCompletedModelClean:
    """Tests for SetupWizardCompletedModel.clean (write-once semantics)."""

    @pytest.mark.django_db
    def test_clean_allows_initial_set(self) -> None:
        """Setting setup_completed_at on a new instance raises no error."""
        import datetime

        instance = SetupWizardCompletedModel(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
            setup_completed_at=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        )
        instance.clean()  # must not raise

    @pytest.mark.django_db
    def test_clean_allows_null_when_row_not_persisted(self) -> None:
        """Clean passes for a new unsaved instance with null timestamp."""
        instance = SetupWizardCompletedModel(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
        )
        instance.clean()  # must not raise

    @pytest.mark.django_db
    def test_clean_blocks_change_after_timestamp_set(self) -> None:
        """Changing setup_completed_at once set raises ValidationError."""
        import datetime

        ts = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        SetupWizardCompletedModel.objects.create(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
            setup_completed_at=ts,
        )
        instance = SetupWizardCompletedModel.objects.get(pk=SetupWizardCompletedModel.SINGLETON_ID)
        instance.setup_completed_at = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)

        with pytest.raises(ValidationError):
            instance.clean()

    @pytest.mark.django_db
    def test_clean_blocks_nullifying_after_timestamp_set(self) -> None:
        """Setting setup_completed_at to None once it was set raises ValidationError."""
        import datetime

        ts = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        SetupWizardCompletedModel.objects.create(
            singleton_id=SetupWizardCompletedModel.SINGLETON_ID,
            setup_completed_at=ts,
        )
        instance = SetupWizardCompletedModel.objects.get(pk=SetupWizardCompletedModel.SINGLETON_ID)
        instance.setup_completed_at = None

        with pytest.raises(ValidationError):
            instance.clean()


class TestSetupWizardCompletedModelMarkOnce:
    """Tests for SetupWizardCompletedModel.mark_setup_complete_once."""

    @pytest.mark.django_db(transaction=True)
    def test_first_call_marks_complete_and_returns_true(self) -> None:
        """First call creates the row, sets the timestamp, and returns True."""
        result = SetupWizardCompletedModel.mark_setup_complete_once()
        assert result is True
        assert SetupWizardCompletedModel.setup_wizard_completed() is True

    @pytest.mark.django_db(transaction=True)
    def test_second_call_is_noop_and_returns_false(self) -> None:
        """Subsequent calls are no-ops and return False."""
        SetupWizardCompletedModel.mark_setup_complete_once()
        result = SetupWizardCompletedModel.mark_setup_complete_once()
        assert result is False

    @pytest.mark.django_db(transaction=True)
    def test_timestamp_is_set_after_call(self) -> None:
        """setup_completed_at is non-null after a successful call."""
        SetupWizardCompletedModel.mark_setup_complete_once()
        instance = SetupWizardCompletedModel.objects.get(pk=SetupWizardCompletedModel.SINGLETON_ID)
        assert instance.setup_completed_at is not None


# ---------------------------------------------------------------------------
# SetupWizardConfigModel
# ---------------------------------------------------------------------------


class TestSetupWizardConfigModelStr:
    """Tests for SetupWizardConfigModel.__str__."""

    def test_str_contains_step_and_demo_flag(self) -> None:
        """String representation includes the current step label and demo flag."""
        instance = SetupWizardConfigModel(
            fresh_install_current_step=SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE,
            inject_demo_data=True,
        )
        result = str(instance)
        assert 'Crypto-Storage' in result
        assert 'True' in result

    def test_str_with_summary_step(self) -> None:
        """String representation reflects the Summary step correctly."""
        instance = SetupWizardConfigModel(
            fresh_install_current_step=SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY,
            inject_demo_data=False,
        )
        result = str(instance)
        assert 'Summary' in result
        assert 'False' in result


class TestSetupWizardConfigModelSave:
    """Tests for SetupWizardConfigModel.save singleton enforcement."""

    @pytest.mark.django_db
    def test_save_with_none_pk_sets_singleton_id(self) -> None:
        """Saving with pk=None silently assigns the singleton primary key."""
        instance = SetupWizardConfigModel()
        instance.pk = None
        instance.save()
        assert instance.pk == SetupWizardConfigModel.SINGLETON_ID

    @pytest.mark.django_db
    def test_save_with_wrong_pk_raises_validation_error(self) -> None:
        """Saving with pk != SINGLETON_ID raises ValidationError."""
        instance = SetupWizardConfigModel(pk=99)
        with pytest.raises(ValidationError):
            instance.save()


class TestSetupWizardConfigModelGetSingleton:
    """Tests for SetupWizardConfigModel.get_singleton."""

    @pytest.mark.django_db
    def test_creates_row_on_first_call(self) -> None:
        """Creates the singleton row when it does not yet exist."""
        assert not SetupWizardConfigModel.objects.exists()
        obj = SetupWizardConfigModel.get_singleton()
        assert obj.pk == SetupWizardConfigModel.SINGLETON_ID

    @pytest.mark.django_db
    def test_returns_same_row_on_subsequent_calls(self) -> None:
        """Returns the same row instead of creating duplicates."""
        first = SetupWizardConfigModel.get_singleton()
        second = SetupWizardConfigModel.get_singleton()
        assert first.pk == second.pk
        assert SetupWizardConfigModel.objects.count() == 1


class TestSetupWizardConfigModelGetCurrentStep:
    """Tests for SetupWizardConfigModel.get_current_step."""

    @pytest.mark.django_db
    def test_default_step_is_crypto_storage(self) -> None:
        """Default step is CRYPTO_STORAGE."""
        step = SetupWizardConfigModel.get_current_step()
        assert step == SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE


class TestSetupWizardConfigModelIsStepSubmitted:
    """Tests for SetupWizardConfigModel.is_step_submitted."""

    def test_returns_false_for_all_steps_by_default(self) -> None:
        """All steps are initially not submitted."""
        instance = SetupWizardConfigModel()
        for step in SetupWizardConfigModel.FreshInstallCurrentStep:
            assert instance.is_step_submitted(step) is False

    def test_returns_true_for_submitted_step(self) -> None:
        """Returns True after the corresponding submitted flag is set."""
        instance = SetupWizardConfigModel(fresh_install_crypto_storage_submitted=True)
        assert instance.is_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE) is True
        assert instance.is_step_submitted(SetupWizardConfigModel.FreshInstallCurrentStep.DEMO_DATA) is False


class TestSetupWizardConfigModelMarkStepSubmitted:
    """Tests for SetupWizardConfigModel.mark_step_submitted."""

    def test_marks_correct_field_for_each_step(self) -> None:
        """mark_step_submitted sets the right Boolean field for every step."""
        step_to_field = {
            SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE: 'fresh_install_crypto_storage_submitted',
            SetupWizardConfigModel.FreshInstallCurrentStep.DEMO_DATA: 'fresh_install_demo_data_submitted',
            SetupWizardConfigModel.FreshInstallCurrentStep.TLS_CONFIG: 'fresh_install_tls_config_submitted',
            SetupWizardConfigModel.FreshInstallCurrentStep.SUMMARY: 'fresh_install_summary_submitted',
        }
        for step, field_name in step_to_field.items():
            instance = SetupWizardConfigModel()
            assert getattr(instance, field_name) is False
            instance.mark_step_submitted(step)
            assert getattr(instance, field_name) is True


class TestSetupWizardConfigModelClean:
    """Tests for SetupWizardConfigModel.clean singleton validation."""

    def test_clean_passes_with_correct_pk(self) -> None:
        """clean() does not raise when pk equals SINGLETON_ID."""
        instance = SetupWizardConfigModel(pk=SetupWizardConfigModel.SINGLETON_ID)
        instance.clean()  # must not raise

    def test_clean_passes_when_pk_is_none(self) -> None:
        """clean() does not raise when pk is None (new instance)."""
        instance = SetupWizardConfigModel()
        instance.pk = None
        instance.clean()  # must not raise

    def test_clean_raises_with_wrong_pk(self) -> None:
        """clean() raises ValidationError when pk is set to a value other than SINGLETON_ID."""
        instance = SetupWizardConfigModel(pk=42)
        with pytest.raises(ValidationError):
            instance.clean()
