"""Provides the `PkiMessageParser` class for parsing PKI messages."""
from abc import ABC, abstractmethod

from pki.models import DomainModel
from request.request_context import BaseCertificateRequestContext, BaseRequestContext
from trustpoint.logger import LoggerMixin


class ParsingComponent(ABC):
    """Abstract base class for components in the composite parsing pattern."""

    @abstractmethod
    def parse(self, context: BaseRequestContext) -> None:
        """Execute parsing logic and store results in the context."""



class DomainParsing(ParsingComponent, LoggerMixin):
    """Parses and validates the domain from the request context object."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract and validate the domain, then add it to the context."""
        domain_str = context.domain_str
        if not domain_str:
            error_msg = 'Domain str missing in request context, deferring domain resolution to authentication step'
            self.logger.warning(error_msg)
            return
        if domain_str == '.aoki':
            self.logger.info('Special domain ".aoki" detected, deferring domain resolution to authentication step')
            return

        domain = self._extract_requested_domain(domain_str)
        context.domain = domain
        self.logger.info("Domain parsing successful: Domain '%s'", domain_str)


    def _extract_requested_domain(self, domain_name: str) -> DomainModel:
        """Validate and fetch the domain object by name."""
        try:
            domain = DomainModel.objects.get(unique_name=domain_name)
        except DomainModel.DoesNotExist as e:
            error_message = f"Domain '{domain_name}' does not exist."
            self.logger.warning("Domain lookup failed: Domain '%s' does not exist", domain_name)
            raise ValueError(error_message) from e
        except DomainModel.MultipleObjectsReturned as e:
            error_message = f"Multiple domains found for '{domain_name}'."
            self.logger.warning("Domain lookup failed: Multiple domains found for '%s'", domain_name)
            raise ValueError(error_message) from e
        else:
            self.logger.debug("Domain lookup successful: Found domain '%s'", domain_name)
            return domain

class CertProfileParsing(ParsingComponent, LoggerMixin):
    """Parses the certificate profile from the request context object."""

    def parse(self, context: BaseRequestContext) -> None:
        """Extract and validate the certificate profile, then add it to the context."""
        if not isinstance(context, BaseCertificateRequestContext):
            # Not a certificate request context; skip parsing profile
            return
        certprofile_str = context.cert_profile_str
        if not certprofile_str:
            error_message = 'Certificate profile is missing in the request context.'
            self.logger.warning('Certificate profile parsing failed: Profile string is missing')
            raise ValueError(error_message)

        self.logger.info("Certificate profile parsing successful: Profile '%s'", certprofile_str)





class CompositeParsing(ParsingComponent, LoggerMixin):
    """Composite parser to group multiple parsing strategies."""

    def __init__(self) -> None:
        """Initialize the composite parser with an empty list of components."""
        self.components: list[ParsingComponent] = []

    def add(self, component: ParsingComponent) -> None:
        """Add a parsing component to the composite parser."""
        self.components.append(component)

    def remove(self, component: ParsingComponent) -> None:
        """Remove a parsing component from the composite parser."""
        if component in self.components:
            self.components.remove(component)
            self.logger.debug('Removed parsing component: %(component_name)s',
                              extra={'component_name': component.__class__.__name__})
        else:
            error_message = f'Attempted to remove non-existent parsing component: {component.__class__.__name__}'
            self.logger.warning(error_message)
            raise ValueError(error_message)


    def parse(self, context: BaseRequestContext) -> None:
        """Execute all child parsers."""
        self.logger.debug('Starting composite parsing with %i components', len(self.components))

        for i, component in enumerate(self.components):
            try:
                component.parse(context)
                self.logger.debug('Parsing component %s completed successfully',
                                  component.__class__.__name__)
            except ValueError as e:
                error_message = f'{component.__class__.__name__}: {e}'
                self.logger.warning('Parsing component %s failed: %s',
                                    component.__class__.__name__, str(e))
                self.logger.exception(
                    'Composite parsing failed at component %s/%s: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e
            except Exception as e:
                error_message = f'Unexpected error in {component.__class__.__name__}: {e}'
                self.logger.exception('Unexpected error in parsing component %s',
                                      component.__class__.__name__)
                self.logger.exception(
                    'Composite parsing failed at component %s/%s: %s',
                    i + 1, len(self.components), component.__class__.__name__)
                raise ValueError(error_message) from e

        self.logger.info('Composite parsing successful. All %i components completed',
                         len(self.components))
