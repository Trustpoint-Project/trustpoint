"""Test suite for backend configuration views."""

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, TestCase
from django.views.generic import TemplateView

from crypto.models import (
    BackendKind,
    CryptoProviderPkcs11ConfigModel,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    Pkcs11AuthSource,
    SoftwareKeyEncryptionSource,
)
from management.views.backend_configuration import BackendConfigurationView


class BackendConfigurationViewTest(TestCase):
    """Test suite for BackendConfigurationView."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.factory = RequestFactory()
        self.view = BackendConfigurationView()
        self.view.request = self.factory.get('/key-storage/')

        # Enable message storage for the request
        self.view.request.session = 'session'
        messages_storage = FallbackStorage(self.view.request)
        self.view.request._messages = messages_storage  # noqa: SLF001

    def test_template_name(self) -> None:
        """Test that the correct template is used."""
        assert self.view.template_name == 'management/backend_configuration.html'

    def test_extra_context_has_page_category(self) -> None:
        """Test extra_context has correct page_category."""
        assert self.view.extra_context['page_category'] == 'management'

    def test_extra_context_has_page_name(self) -> None:
        """Test extra_context has correct page_name."""
        assert self.view.extra_context['page_name'] == 'backend_configuration'

    def test_get_context_data_with_software_config(self) -> None:
        """Test get_context_data with an active software backend profile."""
        profile = CryptoProviderProfileModel.objects.create(
            name='software',
            backend_kind=BackendKind.SOFTWARE,
            active=True,
        )
        software_config = CryptoProviderSoftwareConfigModel.objects.create(
            profile=profile,
            encryption_source=SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
            encryption_source_ref='dev',
        )

        context = self.view.get_context_data()

        assert context['crypto_profile'] == profile
        assert context['software_config'] == software_config
        assert context['is_software_backend']
        assert context['capability_badge'] == 'success'
        assert context['supported_key_capabilities']
        assert context['supported_auto_gen_pki_algorithms']
        assert 'page_title' in context

    def test_get_context_data_with_softhsm_config(self) -> None:
        """Test get_context_data with a PKCS#11 backend profile."""
        profile = CryptoProviderProfileModel.objects.create(
            name='pkcs11',
            backend_kind=BackendKind.PKCS11,
            active=True,
        )
        pkcs11_config = CryptoProviderPkcs11ConfigModel.objects.create(
            profile=profile,
            module_path='/usr/lib/libpkcs11-proxy.so',
            token_label='test-token',  # noqa: S106
            token_serial='',
            slot_id=0,
            auth_source=Pkcs11AuthSource.FILE,
            auth_source_ref='/var/lib/trustpoint/pin',
        )

        context = self.view.get_context_data()

        assert context['crypto_profile'] == profile
        assert context['pkcs11_config'] == pkcs11_config
        assert context['is_pkcs11_backend']
        assert context['pkcs11_token_serial_display'] == '-'  # noqa: S105
        assert context['pkcs11_slot_id_display'] == 0
        assert context['capability_badge'] == 'warning'

    def test_get_context_data_with_physical_hsm_config(self) -> None:
        """Test get_context_data displays configured token serial and slot."""
        profile = CryptoProviderProfileModel.objects.create(
            name='physical-pkcs11',
            backend_kind=BackendKind.PKCS11,
            active=True,
        )
        pkcs11_config = CryptoProviderPkcs11ConfigModel.objects.create(
            profile=profile,
            module_path='/opt/vendor/libpkcs11.so',
            token_label='',
            token_serial='serial-1',  # noqa: S106
            slot_id=1,
            auth_source=Pkcs11AuthSource.FILE,
            auth_source_ref='/var/lib/trustpoint/pin',
        )

        context = self.view.get_context_data()

        assert context['pkcs11_config'] == pkcs11_config
        assert context['pkcs11_token_serial_display'] == 'serial-1'  # noqa: S105
        assert context['pkcs11_slot_id_display'] == 1

    def test_get_context_data_with_hsm_but_no_config_reference(self) -> None:
        """Test get_context_data with PKCS#11 profile but missing config relation."""
        CryptoProviderProfileModel.objects.create(name='pkcs11', backend_kind=BackendKind.PKCS11, active=True)

        context = self.view.get_context_data()

        assert context['is_pkcs11_backend']
        assert context['pkcs11_config'] is None
        assert context['pkcs11_token_serial_display'] == '-'  # noqa: S105

    def test_get_context_data_with_hsm_no_tokens_at_all(self) -> None:
        """Test get_context_data without any crypto profile."""
        context = self.view.get_context_data()

        assert context['crypto_profile'] is None
        assert context['pkcs11_config'] is None

    def test_get_context_data_no_config_exists(self) -> None:
        """Test get_context_data when no crypto backend profile exists."""
        context = self.view.get_context_data()

        assert 'crypto_profile' in context
        assert context['crypto_profile'] is None

        messages_list = list(get_messages(self.view.request))
        assert len(messages_list) == 1
        assert 'No configured crypto backend profile' in str(messages_list[0])

    def test_get_context_data_preserves_parent_context(self) -> None:
        """Test get_context_data preserves context from parent class."""
        context = self.view.get_context_data(custom_key='custom_value')

        assert 'custom_key' in context
        assert context['custom_key'] == 'custom_value'

    def test_backend_configuration_view_inherits_from_template_view(self) -> None:
        """Test BackendConfigurationView is a TemplateView."""
        assert issubclass(BackendConfigurationView, TemplateView)
