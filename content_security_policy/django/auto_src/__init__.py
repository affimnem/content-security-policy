__all__ = [
    # Use for type checking, like in AutoCSPMiddleware
    "AutoSrcDirective",
    # Complete implementations you can actually use in your settings
    "AutoHostScriptSrc",
]

from content_security_policy.directives import ScriptSrc
from content_security_policy.django.auto_src.base import (
    AutoHostSrc,
    AutoSrcDirective,
)


class AutoHostScriptSrc(AutoHostSrc):
    """
    AutoHostSrc for scripts.
    """

    directive = ScriptSrc
    suffix = ".js"
