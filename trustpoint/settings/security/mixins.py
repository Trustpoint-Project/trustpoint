from __future__ import annotations

from typing import TYPE_CHECKING

from django.contrib import messages
from django.shortcuts import redirect
from django.utils.translation import gettext as _

from settings.security.manager import SecurityManager

if TYPE_CHECKING:
    from settings.security import SecurityFeature


class SecurityLevelMixin:
    """A mixin that provides security feature checks for Django views."""

    def __init__(self, security_feature: SecurityFeature = None, *args, **kwargs) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Parameters:
        -----------
        security_feature : SecurityFeatures, optional
            The feature to check against the current security level (default is None).
        no_permisson_url : str, optional
            The URL to which the user is redirected if the feature is not allowed (default is None).
        *args, **kwargs:
            Additional arguments passed to the superclass initializer.
        """
        super().__init__(*args, **kwargs)
        self.sec = SecurityManager()
        self.security_feature = security_feature

    def get_security_level(self):
        """Returns the security mode of the current security level instance.

        Returns:
        --------
        str
            The security mode of the current security level instance.
        """
        return self.sec.get_security_level()


class SecurityLevelMixinRedirect(SecurityLevelMixin):
    """A mixin that provides security feature checks for Django views with redirect feature."""

    def __init__(self, disabled_by_security_level_url=None, *args, **kwargs) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Parameters:
        -----------
        security_feature : SecurityFeatures, optional
            The feature to check against the current security level (default is None).
        no_permisson_url : str, optional
            The URL to which the user is redirected if the feature is not allowed (default is None).
        *args, **kwargs:
            Additional arguments passed to the superclass initializer.
        """
        super().__init__(*args, **kwargs)
        self.disabled_by_security_level_url = disabled_by_security_level_url

    def dispatch(self, request, *args, **kwargs):
        """If the feature is not allowed, the user is redirected to the disabled_by_security_level_url with an error message.

        Parameters:
        -----------
        request : HttpRequest
            The HTTP request object.
        *args, **kwargs:
            Additional arguments passed to the dispatch method.

        Returns:
        --------
        HttpResponse or HttpResponseRedirect
            The HTTP response object, either continuing to the requested view or redirecting.
        """
        if not self.sec.is_feature_allowed(self.security_feature):
            msg = _(
                'Your security setting %s does not allow the feature: %s'
                % (self.get_security_level(), self.security_feature.value)
            )
            messages.error(request, msg)
            return redirect(self.disabled_by_security_level_url)
        return super().dispatch(request, *args, **kwargs)
