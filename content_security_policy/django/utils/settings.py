from typing import Sequence, Tuple, cast

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from content_security_policy.directives import Directive
from content_security_policy.django.auto_src import AutoSrcDirective


def get_csp_setting(
    config_name: str,
) -> Tuple[Tuple[Directive | AutoSrcDirective, ...], ...]:
    """
    Get a CSP setting, make sure it's a one- or two-dimensional sequence of
    directives. Raise helpful exceptions.
    :param config_name: Name of setting to parse
    :return: Always a two-dimensional tuple of directives.
    """

    config = getattr(settings, config_name)
    if isinstance(config[0], (tuple, list)):
        if not all(isinstance(el, (tuple, list)) for el in config):
            raise ImproperlyConfigured(
                f"{config_name} needs to be EITHER a sequence (list/tuple) of "
                f"directives OR a sequence of sequences of directives. "
                f"Mixing sequences and directives is ambiguous."
            )
        config = cast(Sequence[Sequence[Directive | AutoSrcDirective]], config)
        return tuple(tuple(el) for el in config)
    else:
        config = cast(Sequence[Directive | AutoSrcDirective], config)
        return (tuple(config),)
