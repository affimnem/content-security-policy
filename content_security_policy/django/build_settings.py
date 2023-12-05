from content_security_policy.django.settings import *

HOST = ""


CONTENT_SECURITY_POLICY = [
    AutoHostScriptSrc(
        *EXTERNAL_SCRIPTS,
        host="localhost",
        scheme="http",
        watch_apps=INSTALLED_APPS,
    ),
    ScriptSrcAttr(NoneSrc),
    DefaultSrc(KeywordSource.self),
    StyleSrc(KeywordSource.self),
    FrameAncestors(NoneSrc),
    BaseUri(NoneSrc),
    ObjectSrc(NoneSrc),
    ManifestSrc(NoneSrc),
]

CONTENT_SECURITY_POLICY_REPORT_ONLY = CONTENT_SECURITY_POLICY
