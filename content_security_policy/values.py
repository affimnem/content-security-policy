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
    "WebrtcValue",
    "NoneSrc",
    "NoneSrcType",
    "SelfSrc",
    "SelfSrcType",
    "AncestorSource",
    "SandboxToken",
    "SandboxValue",
    "ReportToValue",
    "UriReference",
    "ReportUriValue",
    "UnrecognizedValueItem",
    "TrustedTypesSinkGroup",
    "TrustedTypesPolicyName",
    "TrustedTypesWildcard",
    "TrustedTypesKeyword",
]

from abc import ABC
from typing import Literal, Optional, Type, Union, cast

from content_security_policy.base_classes import ClassAsValue, ValueItem, ValueItemType
from content_security_policy.constants import (
    HASH_ALGORITHMS,
    KEYWORD_SOURCES,
    NONCE_PREFIX,
    NONE,
    SANDBOX_VALUES,
    SELF,
    TRUSTED_TYPES_KEYWORD_VALUES,
    TRUSTED_TYPES_SINK_GROUP_VALUES,
    WEBRTC_VALUES,
    WILDCARD,
)
from content_security_policy.exceptions import BadDirectiveValue, BadSourceExpression
from content_security_policy.patterns import (
    BASE64_VALUE,
    HASH_SOURCE,
    HOST_SOURCE,
    NONCE_SOURCE,
    NONE_SOURCE,
    NOT_SEPARATOR,
    SCHEME,
    SCHEME_SOURCE,
    SELF_SOURCE,
    TOKEN,
    TRUSTED_TYPES_POLICY_NAME,
    URI_REFERENCE,
)
from content_security_policy.patterns import WILDCARD as WILDCARD_RE
from content_security_policy.utils import KeywordMixin


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
class KeywordSource(KeywordMixin, SourceExpression):
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
    _keywords = KEYWORD_SOURCES

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

    _value: str

    def __init__(self, *, _value: Optional[str] = None):
        value = _value or self._value
        super().__init__(value)

    @classmethod
    def from_string(cls, value: str):
        return cls(_value=value)


# According to spec, 'none'  is not a `source-expression`, but a special case of `serialized-source-list`
# https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list
class NoneSrc(SingleValueItem):
    pattern = NONE_SOURCE
    _value = NONE


# Can be passed as class or an instance
NoneSrcType = Union[NoneSrc, Type[NoneSrc]]


class WebrtcValue(KeywordMixin, ValueItem):
    # You can later get an instance of any hash by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    allow = cast("WebrtcValue", "'allow'")
    block = cast("WebrtcValue", "'block'")
    _keywords = WEBRTC_VALUES

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            no_ticks_keyword = value.strip("'")
            value = f"'{no_ticks_keyword}'"
            if not self.pattern.fullmatch(value):
                raise BadSourceExpression(
                    f"{value} does not match {self.pattern.pattern}"
                )
        super().__init__(value)


# https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-elemet
class SandboxToken(KeywordMixin, ValueItem):
    # You can later get an instance of any token by accessing these as class attributes
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
    _keywords = SANDBOX_VALUES

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {self.pattern.pattern}")
        super().__init__(value)


# TODO: Unsure whether I like the Literal[""] here, need to revisit once I work on empty / non-empty directive-values
SandboxValue = Union[SandboxToken, Literal[""]]


# 'self' is a keyword source expression, but it is also a possible hash for frame-ancestors, whereas other
# KeywordSources are not valid static_values for frame-ancestors.
class SelfSrc(SingleValueItem):
    pattern = SELF_SOURCE
    _value = SELF


# Can be passed as class or an instance
SelfSrcType = Union[SelfSrc, Type[SelfSrc]]

# https://w3c.github.io/webappsec-csp/#grammardef-ancestor-source-list
AncestorSource = SchemeSrc | HostSrc | SelfSrcType | NoneSrcType


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


ReportUriValue = UriReference


class UnrecognizedValueItem(ValueItem):
    pattern = NOT_SEPARATOR


class TrustedTypesSinkGroup(KeywordMixin, ValueItem):
    script = cast("TrustedTypesSinkGroup", "'script'")
    _keywords = TRUSTED_TYPES_SINK_GROUP_VALUES

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {self.pattern.pattern}")
        super().__init__(value)


class TrustedTypesExpression(ValueItem, ABC):
    """
    Base class for all tt expressions.
    """


class TrustedTypesPolicyName(TrustedTypesExpression):
    pattern = TRUSTED_TYPES_POLICY_NAME

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        else:
            if not TRUSTED_TYPES_POLICY_NAME.fullmatch(value):
                raise BadSourceExpression(
                    f"TT policy name '{value}' does not match"
                    f" {TRUSTED_TYPES_POLICY_NAME.pattern.pattern}"
                )
        super().__init__(value)


class TrustedTypesWildcard(TrustedTypesExpression, SingleValueItem):
    pattern = WILDCARD_RE
    _value = WILDCARD


class TrustedTypesKeyword(KeywordMixin, TrustedTypesExpression):
    allow_duplicates = cast("TrustedTypesKeyword", "'allow-duplicates'")
    none = cast("TrustedTypesKeyword", "'none'")
    _keywords = TRUSTED_TYPES_KEYWORD_VALUES

    def __init__(self, value: str, _value: Optional[str] = None):
        if _value is not None:
            value = _value
        elif not self.pattern.fullmatch(value):
            raise BadDirectiveValue(f"{value} does not match {self.pattern.pattern}")
        super().__init__(value)
