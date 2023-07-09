"""
Actual directives, I would have loved to generate these classes dynamically, but then autocompletion tools won't
properly pick up on them.
"""
from content_security_policy.base_classes import (
    Directive,
    SingleValueDirective,
    FetchDirective,
)
from content_security_policy.values import (
    SourceList,
    AncestorSourceList,
    SandboxValue,
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


# Reporting directives
class ReportUri(Directive[ReportUriValue]):
    name = "report-uri"


class ReportTo(SingleValueDirective[ReportToValue]):
    name = "report-to"
