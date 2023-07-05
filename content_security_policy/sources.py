__all__ = [
    "SourceExpression",
    "NonceSrc",
    "HashAlgorithm",
    "HashSrc",
    "SchemeSrc",
    "HostSrc",
    "KeywordSource",
]

from abc import ABC
from enum import StrEnum
from typing import Optional, cast

from content_security_policy.constants import NONCE_PREFIX, KEYWORD_SOURCES
from content_security_policy.exceptions import BadSourceExpression
from content_security_policy.patterns import (
    BASE64_VALUE,
    SCHEME,
    HOST_SOURCE,
    KEYWORD_SOURCE as KEYWORD_SOURCE_RE,
)


class SourceExpression(ABC):
    ...


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class NonceSrc(SourceExpression):
    def __init__(self, nonce: str):
        nonce = nonce.strip("'").lstrip(NONCE_PREFIX)
        if not BASE64_VALUE.fullmatch(nonce):
            raise BadSourceExpression(
                f"Nonce value '{nonce}' does not match {BASE64_VALUE.pattern}"
            )

        self._nonce_value: str = nonce

    def __str__(self):
        return f"'{NONCE_PREFIX}{self._nonce_value}'"


# https://w3c.github.io/webappsec-csp/#grammardef-hash-algorithm
class HashAlgorithm(StrEnum):
    sha256 = "sha256"
    sha384 = "sha384"
    sha512 = "sha512"


# https://w3c.github.io/webappsec-csp/#grammardef-nonce-source
class HashSrc(SourceExpression):
    def __init__(self, value: str, algo: Optional[HashAlgorithm | str] = None):
        value = value.strip("'")

        if algo is not None:
            hash_value = value
        else:
            algo, hash_value = value.split("-")

        if not algo in HashAlgorithm:
            raise BadSourceExpression(f"Unknown hash algorithm: '{algo}'")

        if not BASE64_VALUE.fullmatch(hash_value):
            raise BadSourceExpression(
                f"Hash value '{hash_value}' does not match {BASE64_VALUE.pattern}"
            )

        self._algo: HashAlgorithm = algo
        self._hash_value: str = hash_value

    def __str__(self):
        return f"'{self._algo}-{self._hash_value}'"


# https://w3c.github.io/webappsec-csp/#grammardef-scheme-source
class SchemeSrc(SourceExpression):
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
    def __init__(self, host: str):
        if not HOST_SOURCE.fullmatch(host):
            raise BadSourceExpression(f"{host} does not match {HOST_SOURCE.pattern}")
        self._host = host

    def __str__(self):
        return self._host


# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
class KeywordSource(SourceExpression):
    # You can later get an instance of any keyword source by accessing these as class attributes
    # They are spelled out explicitly here so type hints work
    self = cast("KeywordSource", "'self'")
    unsafe_inline = cast("KeywordSource", "'unsafe-inline'")
    unsafe_eval = cast("KeywordSource", "'unsafe-eval'")
    strict_dynamic = cast("KeywordSource", "'strict-dynamic'")
    unsafe_hashes = cast("KeywordSource", "'unsafe-hashes'")
    report_sample = cast("KeywordSource", "'report-sample'")
    unsafe_allow_redirects = cast("KeywordSource", "'unsafe-allow-redirects'")
    wasm_unsafe_eval = cast("KeywordSource", "'wasm-unsafe-eval'")

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

    # Black magic to generate class attributes that are instances of the class
    for keyword in KEYWORD_SOURCES:
        prop_name = keyword.replace("-", "_").strip("'")

        def factory(cls, sneak_me=keyword):
            return cls(sneak_me)

        locals()[prop_name] = classmethod(property(factory))

    del factory
