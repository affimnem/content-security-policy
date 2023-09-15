from __future__ import annotations

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
    "SandboxToken",
    "SandboxValue",
    "ReportToValue",
    "UriReference",
    "ReportUriValue",
    "UnrecognizedValueItem",
]

from abc import ABC
from typing import Literal, Optional, Tuple, Type, Union, cast

from content_security_policy.base_classes import (
    ClassAsValue,
    SelfType,
    ValueItem,
    ValueItemType,
)
from content_security_policy.constants import (
    HASH_ALGORITHMS,
    KEYWORD_SOURCES,
    NONCE_PREFIX,
    NONE,
    SANDBOX_VALUES,
    SELF,
    WEBRTC_VALUES,
)
from content_security_policy.exceptions import BadDirectiveValue, BadSourceExpression
from content_security_policy.patterns import (
    BASE64_VALUE,
    HASH_SOURCE,
    HOST_SOURCE,
    # Appending _RE, so they are easier to distinguish from the constants
    KEYWORD_SOURCE as KEYWORD_SOURCE_RE,
    NONCE_SOURCE,
    NONE_SOURCE,
    NOT_SEPARATOR,
    SANDBOX_VALUE as SANDBOX_VALUE_RE,
    SCHEME,
    SCHEME_SOURCE,
    SELF_SOURCE,
    TOKEN,
    URI_REFERENCE,
    WEBRTC_VALUE as WEBRTC_VALUE_RE,
)
from content_security_policy.utils import AutoInstanceMixin


class SourceExpression(ValueItem, ABC):
    """
    Base class for all source expressions.
    """


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class NonceSrc(SourceExpression):
    pattern = NONCE_SOURCE

    def __init__(self, nonce: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            nonce = nonce.strip("'").lstrip(NONCE_PREFIX)
            if not BASE64_VALUE.fullmatch(nonce):
                raise BadSourceExpression(
                    f"Nonce value '{nonce}' does not match "
                    f"{BASE64_VALUE.pattern.pattern}"
                )
            value = f"'{NONCE_PREFIX}{nonce}'"

        super().__init__(value)


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class HashSrc(SourceExpression):
    pattern = HASH_SOURCE

    def __init__(
        self, hash_value: str, algo: Optional[str] = None, _value: Optional[str] = None
    ):
        if _value is not None:
            value = _value
        else:
            hash_value = hash_value.strip("'")
            if algo is not None:
                hash_value = hash_value
            else:
                algo, hash_value = hash_value.split("-")

            if algo not in HASH_ALGORITHMS:
                raise BadSourceExpression(f"Unknown hash algorithm: '{algo}'")

            if not BASE64_VALUE.fullmatch(hash_value):
                raise BadSourceExpression(
                    f"Hash value '{hash_value}' does not match "
                    f"{BASE64_VALUE.pattern.pattern}"
                )
            value = f"'{algo}-{hash_value}'"

        super().__init__(value)

    @classmethod
    def from_string(cls, str_value: str) -> HashSrc:
        return cls("", "", _value=str_value)


# https://w3c.github.io/webappsec-csp/#grammardef-scheme-source
class SchemeSrc(SourceExpression):
    pattern = SCHEME_SOURCE

    def __init__(self, scheme: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            scheme = scheme.rstrip(":")
            if not SCHEME.fullmatch(scheme):
                raise BadSourceExpression(
                    f"Scheme '{scheme}' does not match {SCHEME.pattern.pattern}"
                )
            value = f"{scheme}:"
        super().__init__(value)


# https://w3c.github.io/webappsec-csp/#grammardef-host-source
class HostSrc(SourceExpression):
    pattern = HOST_SOURCE

    def __init__(self, host: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(host):
            raise BadSourceExpression(f"{host} does not match {self.pattern.pattern}")
        else:
            value = host
        super().__init__(value)


# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
class KeywordSource(AutoInstanceMixin, SourceExpression):
    pattern = KEYWORD_SOURCE_RE

    # You can later get an instance of any hash source by accessing these as class attributes
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

    def __init__(self, keyword: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            no_ticks_keyword = keyword.strip("'")
            keyword = f"'{no_ticks_keyword}'"
            if not self.pattern.fullmatch(keyword):
                raise BadSourceExpression(
                    f"{keyword} does not match {self.pattern.pattern}"
                )
            value = keyword

        super().__init__(value)


class SingleValueItem(ClassAsValue, ValueItem, ABC):
    """
    Value item that only hase a single (semantic) value.
    Because they are case-insensitive, there still is a constructor for lenient parsing.
    """

    def __init__(self, *, _value: Optional[str] = None):
        value = _value or self._value
        super().__init__(value)

    @classmethod
    def from_string(cls: Type[SelfType], value: str) -> SelfType:
        return cls(_value=value)


# According to spec, 'none'  is not a `source-expression`, but a special case of `serialized-source-list`
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
class NoneSrc(SingleValueItem):
    pattern = NONE_SOURCE
    _value = NONE


# Can be passed as class or an instance
NoneSrcType = Union[NoneSrc, Type[NoneSrc]]

# https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
SourceList = Union[Tuple[SourceExpression], NoneSrcType]


class WebrtcValue(AutoInstanceMixin, ValueItem):
    # You can later get an instance of any hash by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    allow = cast("WebrtcValue", "'allow'")
    block = cast("WebrtcValue", "'block'")
    _auto_instance_prop = WEBRTC_VALUES

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            no_ticks_keyword = value.strip("'")
            value = f"'{no_ticks_keyword}'"
            if not WEBRTC_VALUE_RE.fullmatch(value):
                raise BadSourceExpression(
                    f"{value} does not match {KEYWORD_SOURCE_RE.pattern.pattern}"
                )

        super().__init__(_value)


# https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-elemet
class SandboxToken(AutoInstanceMixin, ValueItem):
    # You can later get an instance of any hash by accessing these as class attributes
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

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not SANDBOX_VALUE_RE.fullmatch(value):
            raise BadDirectiveValue(
                f"{value} does not match {SANDBOX_VALUE_RE.pattern.pattern}"
            )
        super().__init__(value)


# TODO: Unsure whether I like the Literal[""] here, need to revisit once I work on empty / non-empty directive-values
SandboxValue = Union[Tuple[SandboxToken], Literal[""]]


# 'self' is a keyword source expression, but it is also a possible hash for frame-ancestors, whereas other
# KeywordSources are not valid static_values for frame-ancestors.
class SelfSrc(SingleValueItem):
    pattern = SELF_SOURCE
    _value = SELF


# Can be passed as class or an instance
SelfSrcType = Union[SelfSrc, Type[SelfSrc]]

# https://w3c.github.io/webappsec-csp/#grammardef-ancestor-source-list
AncestorSource = Union[SchemeSrc, HostSrc, SelfSrcType]
AncestorSourceList = Union[Tuple[AncestorSource], NoneSrcType]


# https://w3c.github.io/webappsec-csp/#directive-report-to
class ReportToValue(ValueItem):
    pattern = TOKEN

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {self.pattern.pattern}")

        super().__init__(value)


# https://w3c.github.io/webappsec-csp/#directive-report-uri
class UriReference(ValueItem):
    pattern = URI_REFERENCE

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {self.pattern.pattern}")

        super().__init__(value)


ReportUriValue = Tuple[UriReference]


class UnrecognizedValueItem(ValueItem):
    pattern = NOT_SEPARATOR
