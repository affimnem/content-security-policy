"""
Actual directives, I would have loved to generate these classes dynamically, but then autocompletion tools won't
properly pick up on them.
"""
from functools import cache
from typing import Type, Union

from content_security_policy.base_classes import (
    Directive,
    SourceListDirective,
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
class ChildSrc(SourceListDirective):
    name = "child-src"


class ConnectSrc(SourceListDirective):
    name = "connect-src"


class DefaultSrc(SourceListDirective):
    name = "default-src"


class FontSrc(SourceListDirective):
    name = "font-src"


class FrameSrc(SourceListDirective):
    name = "frame-src"


class ImgSrc(SourceListDirective):
    name = "img-src"


class ManifestSrc(SourceListDirective):
    name = "manifest-src"


class MediaSrc(SourceListDirective):
    name = "media-src"


class ObjectSrc(SourceListDirective):
    name = "object-src"


class ScriptSrc(SourceListDirective):
    name = "script-src"


class ScriptSrcElem(SourceListDirective):
    name = "script-src-elem"


class ScriptSrcAttr(SourceListDirective):
    name = "script-src-attr"


class StyleSrc(SourceListDirective):
    name = "style-src"


class StyleSrcElem(SourceListDirective):
    name = "style-src-elem"


class StyleSrcAttr(SourceListDirective):
    name = "style-src-attr"


# Other directives
class Webrtc(SingleValueDirective[SourceList]):
    name = "webrtc"


class WorkerSrc(SourceListDirective):
    name = "worker-src"


# Document directives
class BaseUri(SourceListDirective):
    name = "base-uri"


class Sandbox(Directive[SandboxValue]):
    name = "sandbox"


# Navigation directives
class FormAction(SourceListDirective):
    name = "form-action"


class FrameAncestors(Directive[AncestorSourceList]):
    name = "frame-ancestors"

    def __init__(self, *sources: Union[AncestorSource, NoneSrcType]):
        """
        Create frame-ancestors from NoneSrc XOR an arbitrary number of AncestorSource.
        :param sources: Allowed frame ancestors.
        """
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadDirectiveValue(
                f"{NoneSrc} may not be combined with other ancestor sources."
            )
        super().__init__(*sources)


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
