__all__ = ["AutoCSPMiddleware"]

from typing import *

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http.response import HttpResponseBadRequest
from watchdog.observers import Observer

from content_security_policy import Directive, Policy, PolicyList
from content_security_policy.constants import (
    CSP_HEADER,
    CSP_RO_HEADER,
)
from content_security_policy.django.auto_src import AutoSrcDirective
from content_security_policy.django.constants import CSP_CONFIG_NAME, CSP_RO_CONFIG_NAME
from content_security_policy.django.utils.settings import get_csp_setting


class AutoCSPMiddleware:
    """
    Uses the CONTENT_SECURITY_POLICY setting to build a Content-Security-Policy (CSP)
    for the site. Sets up watchers to update dynamic parts of the CSP. Injects CSP
    header into every response.
    """

    def __init__(self, get_response):
        if not settings.DEBUG:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} may only be used with DEBUG = True."
            )

        self.get_response = get_response
        self.policy_lists: Dict[
            str, Tuple[Tuple[Directive | AutoSrcDirective, ...], ...]
        ] = {}

        for config_name, header_name in (
            (CSP_CONFIG_NAME, CSP_HEADER),
            (CSP_RO_CONFIG_NAME, CSP_RO_HEADER),
        ):
            if getattr(settings, config_name, None):
                self.policy_lists[header_name] = get_csp_setting(config_name)

        if not self.policy_lists:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} used but neither {CSP_CONFIG_NAME} nor "
                f"{CSP_RO_CONFIG_NAME} is set in settings."
            )

        for policy_list in self.policy_lists.values():
            for policy in policy_list:
                for directive in policy:
                    if isinstance(directive, AutoSrcDirective):
                        try:
                            # Typing is broken in watchdog
                            observer = self.observer  # type: ignore
                        except AttributeError:
                            observer = self.observer = Observer()  # type: ignore
                        for path in directive.watch_dirs:
                            observer.schedule(directive, path, recursive=True)

        if hasattr(self, "observer"):
            self.observer.start()

    @staticmethod
    def render(policies, scheme: str, host: str):
        return PolicyList(
            *(
                Policy(
                    *(
                        directive.render(scheme=scheme, host=host)
                        if isinstance(directive, AutoSrcDirective)
                        else directive
                        for directive in directives
                    )
                )
                for directives in policies
            )
        )

    def __call__(self, request):
        response = self.get_response(request)
        scheme = request.scheme
        try:
            host = request.META["HTTP_HOST"]
        except KeyError:
            return HttpResponseBadRequest("Host Header Missing from request.")

        for header, policies in self.policy_lists.items():
            response[header] = self.render(policies, scheme, host)

        return response
