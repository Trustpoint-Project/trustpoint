from cryptography import x509
from pyasn1_modules import rfc4210, rfc2511
import logging
import traceback

from pki.pki.cmp.errorhandling.pki_failures import (
    PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
    BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
    CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
    UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
    BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
    NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq
)
from pki.pki.cmp.parsing.pki_body_types import PKIBodyTypes
from pki.pki.cmp.validator.header_validator import GenericHeaderValidator
from pki.pki.cmp.validator.extracerts_validator import ExtraCertsValidator
from pki.pki.cmp.validator.pop_verifier import PoPVerifier
from pki.pki.cmp.errorhandling.error_handler import ErrorHandler
from pki.pki.cmp.protection.protection import RFC4210Protection
from pki.pki.cmp.messagehandler.cert_message_handler import CertMessageHandler
from pki.pki.cmp.messagehandler.revocation_message_handler import RevocationMessageHandler
from pki.pki.cmp.messagehandler.general_message_handler import GeneralMessageHandler
from pki.pki.request.message import HttpStatusCode


class CMPMessageHandler:
    def __init__(self, pki_message: rfc4210.PKIMessage, alias: str = None):
        """
        Initialize the CMPMessageHandler with the necessary components.

        :param alias: str, the alias for the endpoint (optional).
        :param pki_message: rfc4210.PKIMessage, the decoded request data containing the PKI message.
        """
        self.pki_message = pki_message
        self.alias = alias
        self.issuing_ca = None
        self.ca_cert = None
        self.ca_key = None
        self.protection_mode_signature = None
        self.protection_mode_pbm = None
        self.protection_mode_none = None
        self.shared_secret = None
        self.client_cert = None
        self.authorized_clients = None
        self.cert_chain = None

        self.protection = None
        self.header = self.pki_message.getComponentByName('header')
        self.body = None
        self.pki_body_type = None

        self.logger = logging.getLogger("tp").getChild(self.__class__.__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("CMPMessageHandler initialized with alias: %s", self.alias)


    def set_signature_based_protection(self, authorized_clients: list):
        """
        Define params for signature based protection.

        :param authorized_clients: list, a list of pem encoded certificates which are authorized.
        """
        self.protection_mode_signature = True
        self.authorized_clients = authorized_clients
        self.logger.info("Signature-based protection mode set with %d authorized clients", len(authorized_clients))

    def _is_valid_authorized_clients(self):
        self.logger.debug("Validating authorized clients list.")
        if self.authorized_clients:
            if not isinstance(self.authorized_clients, list):
                ValueError(f"authorized_clients must be a list")

            if len(self.authorized_clients) == 0:
                ValueError(f"authorized_clients must contain at least one certificate")

            for cert in self.authorized_clients:
                if not isinstance(cert, x509.Certificate):
                    ValueError(f"Each item in authorized_clients must be an instance of x509.Certificate")

    def set_pbm_based_protection(self, shared_secret: str):
        """
        Define params for a PBM protection.

        :param shared_secret: str, the shared secret (optional, required for PBM mode).
        """
        self.protection_mode_pbm = True
        self.shared_secret = shared_secret
        self.logger.info("PBM-based protection mode set with shared secret.")

    def set_none_protection(self):
        """
        Define params for none protection.

        """
        self.protection_mode_none = True
        raise NotImplementedError("Protection mode None is not supported")


    def set_issuing_ca(self, issuing_ca_object):
        """
        Define params for a local testing setup.

        :param issuing_ca_object: an IssuingCa object.
        """
        self.issuing_ca_object = issuing_ca_object

        self.ca_cert = issuing_ca_object.get_issuing_ca_certificate_serializer().as_crypto()
        self.ca_key = issuing_ca_object.private_key
        self.logger.info("Issuing CA set with certificate and key.")


    def process_request(self) -> tuple[bytes, HttpStatusCode]:
        """
        Processes the incoming CMP request and returns the response.

        :return: str, the response PKI message.
        """
        self.logger.info("Processing CMP request.")
        http_status_code = HttpStatusCode.OK

        try:
            self._is_valid_authorized_clients()
            #self._decode_request()
            self._configure_protection()
            #self._validate_header()
            self._determine_body_type()
            self._validate_extra_certs()
            self._verify_pop()

            response = self._handle_request()
            self.logger.info("Request processed successfully.")

        except (PKIFailure, BadAlg, BadMessageCheck, BadRequest, BadTime, BadCertId,
                BadDataFormat, WrongAuthority, IncorrectData, MissingTimeStamp, BadPOP,
                CertRevoked, CertConfirmed, WrongIntegrity, BadRecipientNonce, TimeNotAvailable,
                UnacceptedPolicy, UnacceptedExtension, AddInfoNotAvailable, BadSenderNonce,
                BadCertTemplate, SignerNotTrusted, TransactionIdInUse, UnsupportedVersion,
                NotAuthorized, SystemUnavail, SystemFailure, DuplicateCertReq) as e:
            self.logger.error(traceback.format_exc())
            response = self._handle_error(e, e.code)
            http_status_code = HttpStatusCode.BAD_REQUEST
        except Exception as e:
            self.logger.error(traceback.format_exc())
            response = self._handle_error(e, 25)
            http_status_code = HttpStatusCode.BAD_REQUEST

        return response, http_status_code

    def _configure_protection(self):
        """
        Configures the protection mechanism for the incoming PKI message.
        """
        self.logger.debug("Configuring protection.")

        self.protection = RFC4210Protection(self.pki_message, self.ca_cert)

        if self.protection_mode_pbm:
            self.logger.debug("Applying PBM protection mode.")
            self.protection.pbm_protection(shared_secret=self.shared_secret)

        if self.protection_mode_signature:
            self.logger.debug("Applying signature protection mode.")
            self.protection.signature_protection(ca_private_key=self.ca_key, authorized_clients=self.authorized_clients)

        self.protection.validate_protection()

    def _validate_header(self):
        """
        Validates the header of the PKI message.
        """
        self.logger.debug("Validating PKI message header.")
        validate_header = GenericHeaderValidator(self.header)
        validate_header.validate()
        self.logger.debug("Header validation completed.")


    def _determine_body_type(self):
        """
        Determines the body type of the PKI message.
        """
        self.logger.debug("Determining body type of PKI message.")
        self.body = self.pki_message.getComponentByName('body')
        self.pki_body_type = PKIBodyTypes()
        self.pki_body_type.get_response(self.body.getName())
        self.logger.info("Body type determined as %s.", self.body.getName())


    def _validate_extra_certs(self):
        """
        Validates the extra certificates in the PKI message.
        """
        self.logger.debug("Validating extra certificates in PKI message.")
        validate_extracerts = ExtraCertsValidator(self.pki_message, self.protection.protection_mode, self.pki_body_type.request_short_name)
        validate_extracerts.validate()
        self.logger.debug("Extra certificates validation completed.")


    def _verify_pop(self):
        """
        Verifies the Proof of Possession (PoP) in the PKI message.
        """
        self.logger.debug("Verifying Proof of Possession (PoP).")
        pop_verifier = PoPVerifier(self.pki_message, self.pki_body_type)
        pop_verifier.verify()
        self.logger.debug("Proof of Possession verification completed.")

    def _handle_request(self) -> bytes:
        """
        Handles the request and generates the appropriate response.

        :return: str, the response PKI message.
        """
        self.logger.debug("Handling request based on body type.")
        incoming = self.body.getComponentByName(self.pki_body_type.request_short_name)
        if not isinstance(incoming, type(self.pki_body_type.request_class)):
            raise BadRequest(f"Expected {self.pki_body_type.request_class}, got {type(incoming)}")

        if isinstance(incoming, rfc2511.CertReqMessages):
            self.logger.debug("Handling certificate request.")
            return self._handle_cert_request()
        elif isinstance(incoming, rfc4210.RevReqContent):
            self.logger.debug("Handling revocation request.")
            return self._handle_revocation_request()
        elif isinstance(incoming, rfc4210.GenMsgContent):
            self.logger.debug("Handling general request.")
            return self._handle_general_request()
        else:
            raise SystemFailure("PKI Body not supported")

    def _handle_cert_request(self) -> bytes:
        """
        Handles a certificate request.

        :return: str, the response PKI message.
        """
        cert_req_msg_handler = CertMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return cert_req_msg_handler.handle(self.issuing_ca_object)

    def _handle_revocation_request(self) -> bytes:
        """
        Handles a revocation request.

        :return: str, the response PKI message.
        """
        revocation_msg_handler = RevocationMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return revocation_msg_handler.handle()

    def _handle_general_request(self) -> bytes:
        """
        Handles a general request.

        :return: str, the response PKI message.
        """
        general_msg_handler = GeneralMessageHandler(self.body, self.header, self.pki_body_type, self.protection)
        return general_msg_handler.handle()

    def _handle_error(self, exception: Exception, error_code: int) -> bytes:
        """
        Handles any errors encountered during the processing of the request.

        :param exception: Exception, the exception that was raised.
        :param error_code: int, the error code to return in the response.
        :return: str, the error response PKI message.
        """
        self.logger.error("Handling error: %s with code %d", str(exception), error_code)
        error_handler = ErrorHandler()
        result = error_handler.handle_error(str(exception), error_code, self.header, self.protection)
        self.logger.debug("Error handled, response generated.")

        return result
