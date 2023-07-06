from enum import StrEnum

# https://w3c.github.io/webappsec-csp/#csp-directives
FETCH_DIRECTIVE_NAMES = (
    "child-src",
    "connect-src",
    "default-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
)
DOCUMENT_DIRECTIVE_NAMES = ("base-uri", "sandbox")
NAVIGATION_DIRECTIVE_NAMES = ("form-action", "frame-ancestors")
REPORTING_DIRECTIVE_NAMES = ("report-uri", "report-to")
OTHER_DIRECTIVE_NAMES = ("webrtc", "worker-src")

DIRECTIVE_NAMES = (
    FETCH_DIRECTIVE_NAMES
    + DOCUMENT_DIRECTIVE_NAMES
    + NAVIGATION_DIRECTIVE_NAMES
    + REPORTING_DIRECTIVE_NAMES
    + OTHER_DIRECTIVE_NAMES
)


class HeaderNames(StrEnum):
    content_security_policy = "Content-Security-Policy"
    csp = content_security_policy
    content_security_policy_report_only = content_security_policy + "-Report-Only"
    csp_ro = content_security_policy_report_only


class CSPLevels(StrEnum):
    level_1 = "level_1"
    level_2 = "level_2"
    level_3 = "level_3"


# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
KEYWORD_SOURCES = [
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'strict-dynamic'",
    "'unsafe-hashes'",
    "'report-sample'",
    "'unsafe-allow-redirects'",
    "'wasm-unsafe-eval'",
]

# https://w3c.github.io/webappsec-csp/#directive-webrtc
WEBRTC_VALUES = ["'allow'", "'block'"]

# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
NONCE_PREFIX = "nonce-"

NONE = "'none'"

SELF = "'self'"

VALUE_SEPARATOR = " "
