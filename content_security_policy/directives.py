"""
Actual directives, I would have loved to generate these classes dynamically, but then autocompletion tools won't
properly pick up on them.
"""
from content_security_policy.base_classes import Directive, SrcDirective


class ChildSrc(SrcDirective):
    name = "child-src"


class ConnectSrc(SrcDirective):
    name = "connect-src"


class DefaultSrc(SrcDirective):
    name = "default-src"


class FontSrc(SrcDirective):
    name = "font-src"


class FrameSrc(SrcDirective):
    name = "frame-src"


class ImgSrc(SrcDirective):
    name = "img-src"


class ManifestSrc(SrcDirective):
    name = "manifest-src"


class MediaSrc(SrcDirective):
    name = "media-src"


class ObjectSrc(SrcDirective):
    name = "object-src"


class ScriptSrc(SrcDirective):
    name = "script-src"


class ScriptSrcElem(SrcDirective):
    name = "script-src-elem"


class ScriptSrcAttr(SrcDirective):
    name = "script-src-attr"


class StyleSrc(SrcDirective):
    name = "style-src"


class StyleSrcElem(SrcDirective):
    name = "style-src-elem"


class StyleSrcAttr(SrcDirective):
    name = "style-src-attr"


class ReportUri(Directive):
    name = "report-uri"


class BaseUri(Directive):
    name = "base-uri"


class WorkerSrc(Directive):
    name = "worker-src"


class Webrtc(Directive):
    name = "webrtc"


class ReportTo(Directive):
    name = "report-to"


class FrameAncestors(Directive):
    name = "frame-ancestors"


class Sandbox(Directive):
    name = "sandbox"


class FormAction(Directive):
    name = "form-action"
