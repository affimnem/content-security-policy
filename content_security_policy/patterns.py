__all__ = [
    "TOKEN",
    "BASE64_VALUE",
    "SCHEME",
    "NONCE_SOURCE",
    "HASH_SOURCE",
    "SCHEME_SOURCE",
    "HOST_SOURCE",
    "NONE_SOURCE",
    "SELF_SOURCE",
    "URI_REFERENCE",
    "WEBRTC_VALUE",
    "SANDBOX_VALUE",
    "ASCII_WHITESPACE",
    "NOT_SEPARATOR",
    "VALUE_ITEM_SEPARATOR",
    "DIRECTIVE_SEPARATOR",
    "POLICY_SEPARATOR",
    "WHITESPACE_HEAD",
    "TRUSTED_TYPES_POLICY_NAME",
    "WILDCARD",
]
# These expressions will be compiled with re.IGNORECASE
__case_insensitive__ = {
    "SANDBOX_VALUE",
    "NONCE_SOURCE",
    "HASH-SOURCE",
    "NONE_SOURCE",
    "SELF_SOURCE",
    "TRUSTED_TYPES_SINK_GROUP",
    "TRUSTED_TYPES_KEYWORD",
    "TRUSTED_TYPES_POLICY_NAME",
}

import re
from typing import cast

from content_security_policy.constants import (
    HASH_ALGORITHMS,
    NONE,
    SANDBOX_VALUES,
    SELF,
    WEBRTC_VALUES,
)

# https://tools.ietf.org/html/rfc5234#appendix-B.1
ALPHA = cast(re.Pattern, r"[A-Za-z]")
DIGIT = cast(re.Pattern, r"[0-9]")

# https://w3c.github.io/webappsec-csp/#grammardef-base64-value
BASE64_VALUE = cast(re.Pattern, rf"({ALPHA}|{DIGIT}|[+\/\-_]){{2, 0}}={{0, 2}}")
NONCE_SOURCE = cast(re.Pattern, f"'nonce-{BASE64_VALUE}'")
HASH_SOURCE = cast(
    re.Pattern, f"'({'|'.join(alg for alg in HASH_ALGORITHMS)})-{BASE64_VALUE}'"
)

# https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2
TOKEN_CHAR = f"[!#$%&'*+\-.^_`|~]|{ALPHA}|{DIGIT}"
TOKEN = cast(re.Pattern, f"({TOKEN_CHAR})+")

# https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
UNRESERVED = f"({ALPHA}|{DIGIT}|[-._~])"
HEXDIG = "[0-9a-fA-F]"
PCT_ENCODED = f"%{HEXDIG}{HEXDIG}"
# Deviating from rfc3986 here, since CSP explicitly excludes ";" and "," from ALL
# directive values:
# https://w3c.github.io/webappsec-csp/#framework-directives
SUB_DELIMS = "[!$&'()*+=]"
PCHAR = f"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|@|:)"
SEGMENT = f"{PCHAR}*"
SEGMENT_NZ = f"{PCHAR}+"  # Non-Zero
PATH_ABSOLUTE = f"/({SEGMENT_NZ}(/{SEGMENT})*)?"
SCHEME = cast(re.Pattern, rf"{ALPHA}({ALPHA}|{DIGIT}|[+-.])*")
DEC_OCTET = f"({DIGIT})|([1-9]{DIGIT})|(1{DIGIT}{{2}})|(2[0-4]{DIGIT})|(25[0-5])"
IP_V4_ADDRESS = f"{DEC_OCTET}.{DEC_OCTET}.{DEC_OCTET}.{DEC_OCTET}"
H16 = f"{HEXDIG}{{1,4}}"
LS_32 = f"({H16}:{H16})|({IP_V4_ADDRESS})"
IP_V6_ADDRESS = (
    f"({H16}:){{6}}{LS_32}"
    f"::({H16}:){{5}}{LS_32}"
    f"({H16})?::({H16}:){{4}}{LS_32}"
    f"(({H16}){{0,1}}{H16})?::({H16}:){{3}}{LS_32}"
    f"(({H16}){{0,2}}{H16})?::({H16}:){{2}}{LS_32}"
    f"(({H16}){{0,3}}{H16})?::{H16}:{LS_32}"
    f"(({H16}){{0,4}}{H16})?::{LS_32}"
    f"(({H16}){{0,5}}{H16})?::{H16}"
    f"(({H16}){{0,6}}{H16})?::"
)
# IP_V_FUTURE = # By the time  this is relevant, I will be dead
# Fixme when I am dead: f"[({IP_V6_ADDRESS})|({IP_V_FUTURE})]"
IP_LITERAL = rf"\[{IP_V6_ADDRESS}\]"
REG_NAME = f"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS})*"
HOST = f"({IP_LITERAL})|({IP_V4_ADDRESS})|({REG_NAME})"
PORT = f"({DIGIT})*"
USERINFO = f"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|:)*"
AUTHORITY = f"({USERINFO})?({HOST})(:{PORT})?"
FRAGMENT = f"({PCHAR}|[/?])*"
QUERY = f"({PCHAR}|[/?])*"
PATH_AB_EMPTY = f"(/{SEGMENT})*"
PATH_ROOTLESS = f"{SEGMENT_NZ}(/{SEGMENT})*"
SEGMENT_NZ_NC = f"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|@)+"
PATH_NOSCHEME = f"{SEGMENT_NZ_NC}(/{SEGMENT})*"
HIER_PART = f"((//{AUTHORITY}{PATH_AB_EMPTY})|{PATH_ABSOLUTE}|{PATH_ROOTLESS})?"
URI = rf"{SCHEME}:{HIER_PART}(\?{QUERY})?(#{FRAGMENT})?"
RELATIVE_PART = f"((//{AUTHORITY}{PATH_AB_EMPTY})|({PATH_ABSOLUTE})|({PATH_NOSCHEME}))?"
RELATIVE_REF = rf"({RELATIVE_PART})(\?{QUERY})?(#{FRAGMENT})?"
URI_REFERENCE = cast(re.Pattern, f"({URI})|({RELATIVE_REF})")

# https://w3c.github.io/webappsec-csp/#grammardef-scheme-source
SCHEME_SOURCE = cast(re.Pattern, f"{SCHEME}:")

# https://w3c.github.io/webappsec-csp/#grammardef-host-source
SCHEME_PART = SCHEME
HOST_CHAR = f"({ALPHA}|{DIGIT}|-)"
HOST_PART = rf"(\*|(\*\.)?{HOST_CHAR}+(\.{HOST_CHAR}+)*)"
PORT_PART = rf"(\*|{DIGIT}+)"
PATH_PART = PATH_ABSOLUTE
HOST_SOURCE = cast(
    re.Pattern, f"({SCHEME_PART}://)?{HOST_PART}(:{PORT_PART})?({PATH_PART})?"
)
# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
NONE_SOURCE = cast(re.Pattern, NONE)

# https://w3c.github.io/webappsec-csp/#grammardef-ancestor-source-list
SELF_SOURCE = cast(re.Pattern, SELF)

# https://w3c.github.io/webappsec-csp/#directive-webrtc
WEBRTC_VALUE = cast(re.Pattern, "|".join(WEBRTC_VALUES))

# https://w3c.github.io/webappsec-csp/#directive-sandbox
SANDBOX_VALUE = cast(re.Pattern, "|".join(SANDBOX_VALUES))

# https://w3c.github.io/webappsec-csp/#grammardef-optional-ascii-whitespace
WHITESPACE_CHARS = "\t\n\x0c\r "
ASCII_WHITESPACE = cast(re.Pattern, f"[{WHITESPACE_CHARS}]")

VALUE_ITEM_SEPARATOR = cast(re.Pattern, f"{ASCII_WHITESPACE}+")
DIRECTIVE_SEPARATOR = cast(re.Pattern, f"{ASCII_WHITESPACE}*;{ASCII_WHITESPACE}*")

POLICY_SEPARATOR = cast(re.Pattern, f"{ASCII_WHITESPACE}*,{ASCII_WHITESPACE}*")
# Used for unrecognized directive names / hash items
NOT_SEPARATOR = cast(re.Pattern, f"[^{WHITESPACE_CHARS};,]*")
WHITESPACE_HEAD = re.compile(f"^{ASCII_WHITESPACE}*", flags=re.MULTILINE)

WILDCARD = cast(re.Pattern, r"\*")
TRUSTED_TYPES_POLICY_NAME = cast(re.Pattern, rf"({ALPHA}|{DIGIT}|-|[\-#=_/@.%])+")

# Workaround for the "want to reuse patters but also want to precompile them"-problem
# Define the patterns as strings, compose them as desired
# Compile them at the end of the module
# Cast all of them to for type-checks
for name in __all__:
    pat = locals()[name]
    if isinstance(pat, re.Pattern):
        continue
    if name in __case_insensitive__:
        locals()[name] = re.compile(pat, flags=re.IGNORECASE)
    else:
        locals()[name] = re.compile(pat)


# Convenience for debug
if __name__ == "__main__":
    for name in __all__:
        print(name)
        print(locals()[name].pattern)
