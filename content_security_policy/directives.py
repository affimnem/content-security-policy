"""
Actual directives, I would have loved to generate these classes dynamically, but then autocompletion tools won't
properly pick up on them.
"""
__all__ = [
    "ChildSrc",
    "ConnectSrc",
    "DefaultSrc",
    "FontSrc",
    "FrameSrc",
    "ImgSrc",
    "ManifestSrc",
    "MediaSrc",
    "ObjectSrc",
    "ScriptSrc",
    "ScriptSrcElem",
    "ScriptSrcAttr",
    "StyleSrc",
    "StyleSrcElem",
    "StyleSrcAttr",
    "BaseUri",
    "Sandbox",
    "FormAction",
    "FrameAncestors",
    "ReportUri",
    "ReportTo",
    "Webrtc",
    "WorkerSrc",
    "directive_by_name",
]

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
    UnrecognizedValueItem,
)


# Fetch Directives
class ChildSrc(SourceListDirective):
    _name = "child-src"


class ConnectSrc(SourceListDirective):
    _name = "connect-src"


class DefaultSrc(SourceListDirective):
    _name = "default-src"


class FontSrc(SourceListDirective):
    _name = "font-src"


class FrameSrc(SourceListDirective):
    _name = "frame-src"


class ImgSrc(SourceListDirective):
    _name = "img-src"


class ManifestSrc(SourceListDirective):
    _name = "manifest-src"


class MediaSrc(SourceListDirective):
    _name = "media-src"


class ObjectSrc(SourceListDirective):
    _name = "object-src"


class ScriptSrc(SourceListDirective):
    _name = "script-src"


class ScriptSrcElem(SourceListDirective):
    _name = "script-src-elem"


class ScriptSrcAttr(SourceListDirective):
    _name = "script-src-attr"


class StyleSrc(SourceListDirective):
    _name = "style-src"


class StyleSrcElem(SourceListDirective):
    _name = "style-src-elem"


class StyleSrcAttr(SourceListDirective):
    _name = "style-src-attr"


# Other directives
class Webrtc(SingleValueDirective[SourceList]):
    _name = "webrtc"


class WorkerSrc(SourceListDirective):
    _name = "worker-src"


# Document directives
class BaseUri(SourceListDirective):
    _name = "base-uri"


class Sandbox(Directive[SandboxValue]):
    _name = "sandbox"


# Navigation directives
class FormAction(SourceListDirective):
    _name = "form-action"


class FrameAncestors(Directive[AncestorSourceList]):
    _name = "frame-ancestors"

    def __init__(self, *sources: Union[AncestorSource, NoneSrcType], **kwargs):
        """
        Create frame-ancestors from NoneSrc XOR an arbitrary number of AncestorSource.
        :param sources: Allowed frame ancestors.
        """
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadDirectiveValue(
                f"{NoneSrc} may not be combined with other ancestor sources."
            )
        super().__init__(*sources, **kwargs)


# Reporting directives
class ReportUri(Directive[ReportUriValue]):
    _name = "report-uri"


class ReportTo(SingleValueDirective[ReportToValue]):
    _name = "report-to"


class UnrecognizedDirective(Directive[UnrecognizedValueItem]):
    """
    A directive whose name is not recognized.
    """

    def __init__(self, name: str, *values):
        self._name = name
        super().__init__(*values, _name=name)

    @property
    def name(self) -> str:
        return self._name


@cache
def directive_by_name(directive_name: str) -> Type[Directive]:
    """
    Get class for directive by its real _name.
    :param directive_name: real _name of the directive, e.g. "script-src".
    :return: Class for the directive.
    """
    class_name = kebab_to_pascal(directive_name)
    try:
        return getattr(__import__(__name__), class_name)
    except AttributeError:
        raise NoSuchDirective(
            f"Can not find class for directive _name {directive_name}"
        )
