"""
Actual directives, I would have loved to generate these classes dynamically, but then autocompletion tools won't
properly pick up on them.
"""
from functools import cache
from typing import Type, Union

from content_security_policy.base_classes import (
    Directive,
    FetchDirective,
    SelfType,
    SingleValueDirective,
)
from content_security_policy.exceptions import BadDirectiveValue, NoSuchDirective
from content_security_policy.utils import kebab_to_pascal
from content_security_policy.values import (
    SourceList,
    SandboxValue,
    AncestorSourceList,
    AncestorSource,
    NoneSrc,
    NoneSrcType,
    ReportToValue,
    ReportUriValue,
)


# Fetch Directives
class ChildSrc(FetchDirective):
    name = "child-src"


class ConnectSrc(FetchDirective):
    name = "connect-src"


class DefaultSrc(FetchDirective):
    name = "default-src"


class FontSrc(FetchDirective):
    name = "font-src"


class FrameSrc(FetchDirective):
    name = "frame-src"


class ImgSrc(FetchDirective):
    name = "img-src"


class ManifestSrc(FetchDirective):
    name = "manifest-src"


class MediaSrc(FetchDirective):
    name = "media-src"


class ObjectSrc(FetchDirective):
    name = "object-src"


class ScriptSrc(FetchDirective):
    name = "script-src"


class ScriptSrcElem(FetchDirective):
    name = "script-src-elem"


class ScriptSrcAttr(FetchDirective):
    name = "script-src-attr"


class StyleSrc(FetchDirective):
    name = "style-src"


class StyleSrcElem(FetchDirective):
    name = "style-src-elem"


class StyleSrcAttr(FetchDirective):
    name = "style-src-attr"


# Other directives
class Webrtc(SingleValueDirective[SourceList]):
    name = "webrtc"


class WorkerSrc(Directive[SourceList]):
    name = "worker-src"


# Document directives
class BaseUri(Directive[SourceList]):
    name = "base-uri"


class Sandbox(Directive[SandboxValue]):
    name = "sandbox"


# Navigation directives
class FormAction(Directive[SourceList]):
    name = "form-action"


class FrameAncestors(Directive[AncestorSourceList]):
    name = "frame-ancestors"

    def __init__(self, *sources: AncestorSource):
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadDirectiveValue(
                f"{NoneSrc} may not be combined with other ancestor sources."
            )
        super().__init__(*sources)

    def __add__(self: SelfType, other: AncestorSource) -> SelfType:
        if self.values and other == NoneSrc:
            raise BadDirectiveValue(
                f"{NoneSrc} may not be combined with other ancestor sources."
            )

        return type(self)(*self.values, other)


# Reporting directives
class ReportUri(Directive[ReportUriValue]):
    name = "report-uri"


class ReportTo(SingleValueDirective[ReportToValue]):
    name = "report-to"


@cache
def directive_by_name(directive_name: str) -> Type[Directive]:
    """
    Get class for directive by its real name.
    :param directive_name: real name of the directive, e.g. "script-src".
    :return: Class for the directive.
    """
    class_name = kebab_to_pascal(directive_name)
    try:
        return getattr(__import__(__name__), class_name)
    except AttributeError:
        raise NoSuchDirective(f"Can not find class for directive name {directive_name}")
