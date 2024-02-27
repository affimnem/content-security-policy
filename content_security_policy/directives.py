"""
Actual directives, I would have loved to generate these classes dynamically, but then
autocompletion tools won't properly pick up on them.
"""
__all__ = [
    "SourceListDirective",
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
    "TrustedTypes",
    "RequireTrustedTypesFor",
    "UnrecognizedDirective",
]

from abc import ABC
from typing import Optional, Union

from content_security_policy.base_classes import (
    Directive,
    SingleValueDirective,
)
from content_security_policy.exceptions import (
    BadDirectiveValue,
    BadSourceList,
)
from content_security_policy.values import (
    AncestorSource,
    NoneSrc,
    NoneSrcType,
    ReportToValue,
    ReportUriValue,
    SandboxValue,
    SourceExpression,
    TrustedTypesSinkGroup,
    UnrecognizedValueItem,
)


# This is not called FetchDirective because not all directives accepting a Source List
# are categorised as Fetch Directives by the spec (worker-src, base-uri, form-action)
class SourceListDirective(Directive[SourceExpression], ABC):
    """
    A directive whose hash is a
    """

    def __init__(self, *sources, **kwargs):
        # https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadSourceList(
                f"{NoneSrc} may not be combined with other source expressions."
            )
        super().__init__(*sources, **kwargs)

    def __add__(self, other):
        return type(self)(*self.values, other, _name=self._name)


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
class Webrtc(SingleValueDirective[SourceExpression]):
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


class FrameAncestors(Directive[AncestorSource]):
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


class RequireTrustedTypesFor(Directive[TrustedTypesSinkGroup]):
    _name = "require-trusted-types-for"


class TrustedTypes(Directive[TrustedTypesSinkGroup]):
    _name = "trusted-types"


class UnrecognizedDirective(Directive[UnrecognizedValueItem]):
    """
    A directive whose name is not recognized.
    """

    def __init__(self, *values, name: Optional[str] = None, **kwargs):
        if name is None and "_name" not in kwargs:
            raise ValueError(
                f"You must pass either '_name' or 'name' as a kwarg to "
                f"{type(self).__name__}. 'name' takes precedence."
            )

        if name is not None:
            kwargs["_name"] = name
        super().__init__(*values, **kwargs)

    @property
    def name(self) -> str:
        return self._name
