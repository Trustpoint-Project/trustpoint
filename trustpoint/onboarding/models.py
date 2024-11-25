"""This module contains models for the Onboarding app."""

from __future__ import annotations

import logging
import secrets
import threading
from enum import IntEnum
from typing import TYPE_CHECKING

from devices import DeviceOnboardingStatus, OnboardingProtocol
from devices.models import Device
from django.db import models
from django.utils.translation import gettext as _
from pki import ReasonCode
from pki.models import CertificateModel, DomainModel
from pki.serializer import CredentialSerializer

from onboarding.crypto_backend import CryptoBackend as Crypt
from onboarding.crypto_backend import OnboardingError

if TYPE_CHECKING:
    from typing import TypeVar

onboarding_timeout = 1800  # seconds, TODO: add to configuration

log = logging.getLogger('tp.onboarding')


class OnboardingProcessState(IntEnum):
    """Enum representing the state of an onboarding process.

    Negative values indicate an error state.
    """

    NO_SUCH_PROCESS = -3
    CANCELED = -2
    FAILED = -1
    STARTED = 0
    HMAC_GENERATED = 1
    TRUST_STORE_SENT = 2
    DEVICE_VALIDATED = 3
    LDEVID_SENT = 4
    COMPLETED = 5  # aka cert chain was requested


class NoOnboardingProcessError(Exception):
    """Exception raised when no onboarding process is found for a certain device, ID, or url extension."""

    def __init__(self, message: str = 'No onboarding process found.') -> None:
        """Initializes a new NoOnboardingProcessError with a given message."""
        self.message = message
        super().__init__(self.message)


# NOT a database-backed model
class OnboardingProcess():
    """Represents an onboarding process for a device.

    This model is not written to the database.
    We may consider restructuring this in the future to write some of the values, e.g. for logging purposes.
    """

    id_counter = 1  # only unique within the current server runtime

    def __init__(self, dev: Device, domain_id: int, onboarding_protocol: OnboardingProtocol) -> None:
        """Initializes a new onboarding process for a device.

        Generates secrets, starts two threads for trust store HMAC generation and a timer for timeout.
        """
        super().__init__()
        self.device = dev
        self.domain_id = domain_id
        self.onboarding_protocol = onboarding_protocol
        self.id = OnboardingProcess.id_counter
        self.state = OnboardingProcessState.STARTED
        self.error_reason = ''
        self.url = dev.device_name
        self.timer = threading.Timer(onboarding_timeout, self._timeout)
        # TODO (Air): instead of daemon, consider using events to exit gracefully on shutdown
        self.timer.daemon = True
        self.timer.start()
        self.active = True
        OnboardingProcess.id_counter += 1
        self.download_token = secrets.token_hex(32)
        self.cert_model = None
        log.info(f'Onboarding process {self.id} started for device {self.device.device_name}.')

    def __str__(self) -> str:
        """Returns the onboarding process in human-readable format."""
        return f'OnboardingProcess {self.id} for device {self.device.device_name}'

    def __repr__(self) -> str:
        """Returns the onboarding process in human-readable format."""
        return self.__str__()

    @staticmethod
    def get_by_id(process_id: int) -> OnboardingProcess | None:
        """Returns the onboarding process with a given ID."""
        for process in onboarding_processes:
            if process.id == process_id:
                return process
        return None

    @staticmethod
    def get_by_url_ext(url: str) -> OnboardingProcess | None:
        """Returns the onboarding process with a given URL extension."""
        for process in onboarding_processes:
            if process.url == url:
                return process
        return None

    if TYPE_CHECKING:
        OnboardingProcessTypes = TypeVar('OnboardingProcessTypes', bound='OnboardingProcess')

    @staticmethod
    def make_onboarding_process(device: Device, domain_id: int, process_type: type[OnboardingProcessTypes], onboarding_protocol: str) -> OnboardingProcessTypes:
        """Creates a new one onboarding process.

        Args:
            device (Device): The device to create the onboarding process for.
            process_type (classname): The (class) type of the onboarding process to create.

        Returns:
            OnboardingProcessTypes: The onboarding process instance for the device.
        """
        try:
            onboarding_protocol = OnboardingProtocol(onboarding_protocol)
        except ValueError:
            msg = f'{onboarding_protocol} No valid onboarding protocol found.'
            log.exception(_(msg))

        onboarding_process = process_type(device, domain_id, onboarding_protocol)
        onboarding_processes.append(onboarding_process)
        # TODO(Air): very unnecessary save required to update onboarding status in table
        # Problem: if server is restarted during onboarding, status is stuck at running
        device.save()

        return onboarding_process

    def cancel(self) -> tuple[OnboardingProcessState, OnboardingProcess]:
        """Cancels the onboarding process and removes it from the list."""
        self.active = False
        self.timer.cancel()
        onboarding_processes.remove(self)
        # TODO: revoke cert
        if self.state != OnboardingProcessState.COMPLETED and self.cert_model:
            # actual cancellation (cancel() may be called just to remove the process from onboarding_processes)
            self. state = OnboardingProcessState.CANCELED
            self.cert_model.revoke(ReasonCode.CESSATION)
            log.info(f'Onboarding process {self.id} for device {self.device.device_name} canceled.')
        else:
            log.info(f'Onboarding process {self.id} removed from list.')

        return (self.state, self)

    def get_pkcs12(self) -> bytes | None:
        """Returns the keypair and LDevID certificate as PKCS12 serialized bytes and ends the onboarding process."""
        log.debug(f'PKCS12 requested for onboarding process {self.id}.')
        self.gen_thread.join()
        self._success()
        return self.cred_serializer.as_pkcs12()

    def get_pem_zip(self) -> bytes | None:
        """Returns the certificate, chain and key as PEM-formatted bytes in a zip file."""
        log.debug(f'PKCS12 requested for onboarding process {self.id}.')
        self.gen_thread.join()
        self._success()
        return self.cred_serializer.as_pem_zip()

    def _gen_keypair_and_ldevid(self) -> None:
        """Generates a keypair and LDevID certificate for the device."""
        try:
            if not self.device.device_serial_number:
                self.device.device_serial_number = 'tpdl_' + secrets.token_urlsafe(12)
            pki_response = Crypt.gen_keypair_and_ldevid(self.device, self.domain_id, str(self))
            self.cert_model = pki_response.cert_model
            self.cred_serializer = CredentialSerializer(pki_response.raw_response)
            self.state = OnboardingProcessState.LDEVID_SENT
            log.info(f'LDevID issued for device {self.device.device_name} in onboarding process {self.id}.')
        except Exception as e:  # noqa: BLE001
            msg = 'Error generating device key or LDevID.'
            self._fail(msg)
            raise OnboardingError(msg) from e

    def _fail(self, reason: str = '') -> None:
        """Cancels the onboarding process with a given reason."""
        self.state = OnboardingProcessState.FAILED
        self.active = False
        self.error_reason = reason
        self.timer.cancel()
        self.device.device_onboarding_status = DeviceOnboardingStatus.ONBOARDING_FAILED
        self.device.revoke_ldevid(ReasonCode.CESSATION)
        self.device.save()
        log.error(f'Onboarding process {self.id} for device {self.device.device_name} failed: {reason}')

    def _success(self) -> None:
        """Completes the onboarding process."""
        self.state = OnboardingProcessState.COMPLETED
        self.active = False
        self.timer.cancel()
        self.device.device_onboarding_status = DeviceOnboardingStatus.ONBOARDED
        self.device.save()
        log.info(f'Onboarding process {self.id} for device {self.device.device_name} completed.')

    def _timeout(self) -> None:
        """Cancels the onboarding process due to timeout, called by timer thread."""
        self._fail('Process timed out.')

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    datetime_started = models.DateTimeField(auto_now_add=True)


class LDevIDOnboardingProcessMixin():
    """Mixin that provides all methods required for onboarding process types using the /api/onboarding/ldevid endpoint"""

    cert_model: CertificateModel

    def __init__(self, dev: Device):
        """Initializes the mixin"""
        self.otp = secrets.token_hex(8)
        self.salt = self.url
        self.gen_thread = threading.Thread(target=self._calc_hmac, daemon=True)
        self.gen_thread.start()
        self.hmac = None

    def _calc_hmac(self) -> None:
        """Calculates the HMAC signature of the trust store.

        Runs in separate gen_thread thread started by __init__ as it typically takes about a second.
        """
        try:
            self.hmac = Crypt.pbkdf2_hmac_sha256(self.otp, self.salt, Crypt.get_trust_store().encode())
        except Exception as e:  # noqa: BLE001
            msg = 'Error generating trust store HMAC.'
            self._fail(msg)
            raise OnboardingError(msg) from e

        if self.state == OnboardingProcessState.STARTED:
            self.state = OnboardingProcessState.HMAC_GENERATED

    def get_hmac(self) -> str:
        """Returns the HMAC signature of the trust store and the PBKDF2 of the trust store OTP and salt."""
        self.gen_thread.join()
        return self.hmac

    def check_ldevid_auth(self, uname: str, passwd: str) -> bool:
        """Checks the provided credentials against OTP stored in the onboarding process."""
        if not self.active:
            return False
        if uname == self.salt and passwd == self.otp:
            self.state = OnboardingProcessState.DEVICE_VALIDATED
            log.debug(f'Device {self.device.device_name} validated for onboarding process {self.id}.')
            return True

        self._fail('Client provided invalid credentials.')
        return False

    def sign_ldevid(self, csr: bytes) -> bytes | None:
        """Issues LDevID certificate with the onboarding CA based on provided CSR."""
        if not self.active:
            return None
        if self.state != OnboardingProcessState.DEVICE_VALIDATED:
            return None
        try:
            pki_response = Crypt.sign_ldevid_from_csr(csr, self.device)
            self.cert_model = pki_response.cert_model
            ldevid = pki_response.raw_response
        except Exception as e:
            self._fail(str(e))  # TODO(Air): is it safe to print exception messages to the user UI?
            log.exception('Error signing LDevID certificate.', exc_info=True)
            raise
        if ldevid:
            self.state = OnboardingProcessState.LDEVID_SENT
            log.info(f'LDevID issued for device {self.device.device_name} in onboarding process {self.id}.')
        else:
            self._fail('No LDevID was generated.')
        return ldevid

    def get_cert_chain(self) -> bytes | None:
        """Returns the certificate chain of the LDevID certificate."""
        if not self.active:
            return None
        if self.state != OnboardingProcessState.LDEVID_SENT:
            return None
        try:
            chain = Crypt.get_cert_chain(self.device)
        except Exception as e:
            self._fail(str(e))
            raise

        self._success()
        if isinstance(self, AokiOnboardingProcess):
            self.cancel()
        return chain


class ManualOnboardingProcess(LDevIDOnboardingProcessMixin, OnboardingProcess):
    """Onboarding process for a device using the full manual onboarding with OTP and HMAC trust store verification."""

    def __init__(self, dev: Device, domain_id, onboarding_protocol) -> None:
        """Initializes a new manual onboarding process for a device."""
        OnboardingProcess.__init__(self, dev, domain_id, onboarding_protocol)
        LDevIDOnboardingProcessMixin.__init__(self, dev)
        print('init ManualOnboardingProcess')
        self.tsotp = secrets.token_hex(8)
        self.tssalt = secrets.token_hex(8)
        self.gen_thread = threading.Thread(target=self._calc_hmac, daemon=True)
        self.gen_thread.start()
        self.hmac = None


class DownloadOnboardingProcess(OnboardingProcess):
    """Onboarding process for a device using the download onboarding method."""
    #_device: Device

    def __init__(self, dev: Device, domain_id: int, onboarding_protocol: OnboardingProtocol) -> None:
        """Initializes a new download onboarding process for a device."""
        super().__init__(dev, domain_id, onboarding_protocol)
        #self._device = dev
        self.gen_thread = threading.Thread(target=self._gen_keypair_and_ldevid)
        self.gen_thread.start()
        self.cred_serializer = None


class BrowserOnboardingProcess(OnboardingProcess):
    """Onboarding process for a device using the download onboarding method."""
    MAXPWTRIES = 3

    def __init__(self, dev: Device, domain_id: int, onboarding_protocol: OnboardingProtocol) -> None:
        """Initializes a new download onboarding process for a device."""
        super().__init__(dev, domain_id, onboarding_protocol)
        self._browser_otp = None
        self.password_tries = 0

    def start_onboarding(self):
        self._browser_otp = None
        self.gen_thread = threading.Thread(target=self._gen_keypair_and_ldevid)
        self.gen_thread.start()
        self.cred_serializer = None

    def set_otp(self, otp: str) -> None:
        self._browser_otp = otp

    def check_otp(self, otp: str) -> tuple:
        self.password_tries += 1
        if self.password_tries < self.MAXPWTRIES:
            if self._browser_otp  and self._browser_otp == otp:
                return (True, None)
        else:
            self.cancel()
            self._fail()
        return (False, self.MAXPWTRIES - self.password_tries)


class ZeroTouchOnboardingProcess(OnboardingProcess):
    """Parent of all zero-touch onboarding process types."""


class AokiOnboardingProcess(LDevIDOnboardingProcessMixin, ZeroTouchOnboardingProcess):
    """Onboarding process for a device using the AOKI protocol."""

    _idevid_cert: bytes
    _server_nonce : str

    def __init__(self, device: Device) -> None:
        """Initializes a new AOKI onboarding process for a device."""
        super().__init__(device)
        self._idevid_cert = None
        self._server_nonce = Crypt.get_nonce()

    def get_server_nonce(self) -> str:
        """Returns the server nonce."""
        return self._server_nonce
    
    def set_idevid_cert(self, idevid_cert: bytes) -> None:
        """Sets the device's IDevID certificate."""
        self._idevid_cert = idevid_cert

    def verify_client_signature(self, message: bytes, signature: bytes) -> None:
        """Verifies the client signature of the server nonce message"""
        try:
            Crypt.verify_signature(message=message, cert=self._idevid_cert, signature=signature)
        except Exception as e:
            self._fail(str(e))
            self.cancel()
            raise OnboardingError from e

    @staticmethod
    def get_by_nonce(server_nonce: str) -> AokiOnboardingProcess | None:
        for op in onboarding_processes:
            if (isinstance(op, AokiOnboardingProcess)
                and op._server_nonce == server_nonce):
                    return op
        return None


onboarding_processes = []
