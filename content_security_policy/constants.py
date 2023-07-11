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

# All these directives have a serialized-source-list as value
SOURCE_LIST_DIRECTIVES = FETCH_DIRECTIVE_NAMES + (
    "worker-src",
    "form-action",
    "base-uri",
)

# https://w3c.github.io/webappsec-csp/#grammardef-hash-algorithm
HASH_ALGORITHMS = (
    "sha256",
    "sha384",
    "sha512",
)

# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
KEYWORD_SOURCES = (
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'strict-dynamic'",
    "'unsafe-hashes'",
    "'report-sample'",
    "'unsafe-allow-redirects'",
    "'wasm-unsafe-eval'",
)

# https://w3c.github.io/webappsec-csp/#directive-webrtc
WEBRTC_VALUES = ["'allow'", "'block'"]

# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
NONCE_PREFIX = "nonce-"

NONE = "'none'"

SELF = "'self'"

DEFAULT_VALUE_SEPARATOR = " "
DEFAULT_POLICY_SEPARATOR = "; "

# https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-elemet
SANDBOX_VALUES = (
    "allow-downloads",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-popups-to-escape-sandbox",
    "allow-presentation",
    "allow-same-origin",
    "allow-scripts",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
)
