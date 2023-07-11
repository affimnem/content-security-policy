__all__ = [
    "ValueItem",
    "ValueItemType",
    "NonceSrc",
    "HashSrc",
    "SchemeSrc",
    "HostSrc",
    "KeywordSource",
    "SourceExpression",
    "SourceList",
    "WebrtcValue",
    "NoneSrc",
    "NoneSrcType",
    "SelfSrc",
    "SelfSrcType",
    "AncestorSource",
    "AncestorSourceList",
    "SandboxValue",
    "ReportToValue",
    "UriReference",
    "ReportUriValue",
    "UnrecognizedValueItem",
]

from abc import ABC
import re
from typing import Optional, Tuple, Union, cast, Literal, Type

from content_security_policy.constants import (
    HASH_ALGORITHMS,
    NONCE_PREFIX,
    KEYWORD_SOURCES,
    NONE,
    SELF,
    WEBRTC_VALUES,
    SANDBOX_VALUES,
)
from content_security_policy.exceptions import BadDirectiveValue, BadSourceExpression
from content_security_policy.patterns import (
    TOKEN,
    BASE64_VALUE,
    SCHEME,
    NONCE_SOURCE,
    HASH_SOURCE,
    SCHEME_SOURCE,
    HOST_SOURCE,
    NONE_SOURCE,
    SELF_SOURCE,
    URI_REFERENCE,
    NOT_SEPARATOR,
    # Appending _RE, so they are easier to distinguish from the constants
    KEYWORD_SOURCE as KEYWORD_SOURCE_RE,
    WEBRTC_VALUE as WEBRTC_VALUE_RE,
    SANDBOX_VALUE as SANDBOX_VALUE_RE,
)
from content_security_policy.utils import SingleValueClass, AutoInstanceMixin


class ValueItem(ABC):
    """
    Base class for "items" in directive values. To clarify the distinction from a directive value, consider:
    script-src 'self' http://example.com
    The value of this script-src directive is "'self' http://example.com", whereas "'self'" and "http://example.com"
    are the "items" of the value.
    The two are not mutually exclusive. Some items may also be valid values by themselves.
    """

    # Pattern used to identify these values when parsing
    _pattern: re.Pattern
    # String from which the value was created
    _parsed_string: Optional[str]


# Some classes for directive values are valid value items themselves, use this to cover both in type hints
ValueItemType = Union[ValueItem, Type[ValueItem]]


class SourceExpression(ValueItem, ABC):
    """
    Base class for all source expressions.
    """


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class NonceSrc(SourceExpression):
    _pattern = NONCE_SOURCE

    def __init__(self, nonce: str):
        nonce = nonce.strip("'").lstrip(NONCE_PREFIX)
        if not BASE64_VALUE.fullmatch(nonce):
            raise BadSourceExpression(
                f"Nonce value '{nonce}' does not match {BASE64_VALUE.pattern}"
            )

        self._nonce_value: str = nonce

    def __str__(self):
        return f"'{NONCE_PREFIX}{self._nonce_value}'"


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class HashSrc(SourceExpression):
    _pattern = HASH_SOURCE

    def __init__(self, value: str, algo: Optional[str] = None):
        value = value.strip("'")

        if algo is not None:
            hash_value = value
        else:
            algo, hash_value = value.split("-")

        if not algo in HASH_ALGORITHMS:
            raise BadSourceExpression(f"Unknown hash algorithm: '{algo}'")

        if not BASE64_VALUE.fullmatch(hash_value):
            raise BadSourceExpression(
                f"Hash value '{hash_value}' does not match {BASE64_VALUE.pattern}"
            )

        self._algo: str = algo
        self._hash_value: str = hash_value

    def __str__(self):
        return f"'{self._algo}-{self._hash_value}'"


# https://w3c.github.io/webappsec-csp/#grammardef-scheme-source
class SchemeSrc(SourceExpression):
    _pattern = SCHEME_SOURCE

    def __init__(self, scheme: str):
        scheme = scheme.rstrip(":")
        if not SCHEME.fullmatch(scheme):
            raise BadSourceExpression(
                f"Scheme '{scheme}' does not match {SCHEME.pattern}"
            )

        self._scheme: str = scheme

    def __str__(self):
        return f"{self._scheme}:"


# https://w3c.github.io/webappsec-csp/#grammardef-host-source
class HostSrc(SourceExpression):
    _pattern = HOST_SOURCE

    def __init__(self, host: str):
        if not HOST_SOURCE.fullmatch(host):
            raise BadSourceExpression(f"{host} does not match {HOST_SOURCE.pattern}")
        self._host = host

    def __str__(self):
        return self._host


# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
class KeywordSource(AutoInstanceMixin, SourceExpression):
    _pattern = KEYWORD_SOURCE_RE

    # You can later get an instance of any value source by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    self = cast("KeywordSource", "'self'")
    unsafe_inline = cast("KeywordSource", "'unsafe-inline'")
    unsafe_eval = cast("KeywordSource", "'unsafe-eval'")
    strict_dynamic = cast("KeywordSource", "'strict-dynamic'")
    unsafe_hashes = cast("KeywordSource", "'unsafe-hashes'")
    report_sample = cast("KeywordSource", "'report-sample'")
    unsafe_allow_redirects = cast("KeywordSource", "'unsafe-allow-redirects'")
    wasm_unsafe_eval = cast("KeywordSource", "'wasm-unsafe-eval'")
    _auto_instance_prop = KEYWORD_SOURCES

    def __init__(self, keyword: str):
        keyword = str(keyword)
        no_ticks_keyword = keyword.strip("'")
        keyword = f"'{no_ticks_keyword}'"
        if not KEYWORD_SOURCE_RE.fullmatch(keyword):
            raise BadSourceExpression(
                f"{keyword} does not match {KEYWORD_SOURCE_RE.pattern}"
            )

        self._keyword = no_ticks_keyword

    def __str__(self):
        return f"'{self._keyword}'"


# According to spec, 'none'  is not a `source-expression`, but a special case of `serialized-source-list`
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
class NoneSrc(SingleValueClass, ValueItem):
    _pattern = NONE_SOURCE
    _value = NONE


# Can be passed as class or an instance
NoneSrcType = Union[NoneSrc, Type[NoneSrc]]

# https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
SourceList = Union[Tuple[SourceExpression], NoneSrcType]


class WebrtcValue(AutoInstanceMixin, ValueItem):
    # You can later get an instance of any value by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    allow = cast("WebrtcValue", "'allow'")
    block = cast("WebrtcValue", "'block'")
    _auto_instance_prop = WEBRTC_VALUES

    def __init__(self, value: str):
        value = str(value)
        no_ticks_keyword = value.strip("'")
        value = f"'{no_ticks_keyword}'"
        if not WEBRTC_VALUE_RE.fullmatch(value):
            raise BadSourceExpression(
                f"{value} does not match {KEYWORD_SOURCE_RE.pattern}"
            )
        self._keyword = no_ticks_keyword

    def __str__(self):
        return f"'{self._keyword}'"


# https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-elemet
class SandboxToken(AutoInstanceMixin, ValueItem):
    # You can later get an instance of any value by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    allow_downloads = cast("SandboxToken", "allow-downloads")
    allow_forms = cast("SandboxToken", "allow-forms")
    allow_modals = cast("SandboxToken", "allow-modals")
    allow_orientation_lock = cast("SandboxToken", "allow-orientation-lock")
    allow_pointer_lock = cast("SandboxToken", "allow-pointer-lock")
    allow_popups = cast("SandboxToken", "allow-popups")
    allow_popups_to_escape_sandbox = cast(
        "SandboxToken", "allow-popups-to-escape-sandbox"
    )
    allow_presentation = cast("SandboxToken", "allow-presentation")
    allow_same_origin = cast("SandboxToken", "allow-same-origin")
    allow_scripts = cast("SandboxToken", "allow-scripts")
    allow_top_navigation = cast("SandboxToken", "allow-top-navigation")
    allow_top_navigation_by_user_activation = cast(
        "SandboxToken", "allow-top-navigation-by-user-activation"
    )
    allow_top_navigation_to_custom_protocols = cast(
        "SandboxToken", "allow-top-navigation-to-custom-protocols"
    )
    _auto_instance_prop = SANDBOX_VALUES

    def __init__(self, value: str):
        value = str(value)
        if not SANDBOX_VALUE_RE.fullmatch(value):
            raise BadDirectiveValue(
                f"{value} does not match {SANDBOX_VALUE_RE.pattern}"
            )
        self._token = value.lower()

    def __str__(self):
        # Unlike other "keywords" in CSP, sandbox values are not wrapped in single ticks
        return self._token


# TODO: Unsure whether I like the Literal[""] here, need to revisit once I work on empty / non-empty directive-values
SandboxValue = Union[Tuple[SandboxToken], Literal[""]]


# 'self' is a keyword source expression, but it is also a possible value for frame-ancestors, whereas other
# KeywordSources are not valid values for frame-ancestors.
class SelfSrc(SingleValueClass, ValueItem):
    _pattern = SELF_SOURCE
    _value = SELF


# Can be passed as class or an instance
SelfSrcType = Union[SelfSrc, Type[SelfSrc]]

# https://w3c.github.io/webappsec-csp/#grammardef-ancestor-source-list
AncestorSource = Union[SchemeSrc, HostSrc, SelfSrcType]
AncestorSourceList = Union[Tuple[AncestorSource], NoneSrcType]


# https://w3c.github.io/webappsec-csp/#directive-report-to
class ReportToValue(ValueItem):
    _pattern = TOKEN

    def __init__(self, value: str):
        value = str(value)
        if not TOKEN.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {TOKEN.pattern}")
        self._token = value.lower()

    def __str__(self):
        return self._token


# https://w3c.github.io/webappsec-csp/#directive-report-uri
class UriReference(ValueItem):
    _pattern = URI_REFERENCE

    def __init__(self, value: str):
        value = str(value)
        if not URI_REFERENCE.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {URI_REFERENCE.pattern}")
        self._uri_reference = value.lower()

    def __str__(self):
        return self._uri_reference


ReportUriValue = Tuple[UriReference]


class UnrecognizedValueItem(ValueItem):
    _pattern = NOT_SEPARATOR
