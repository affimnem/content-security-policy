__all__ = [
    "TOKEN",
    "BASE64_VALUE",
    "SCHEME",
    "HOST_SOURCE",
    "URI_REFERENCE",
    "KEYWORD_SOURCE",
    "WEBRTC_VALUE",
    "SANDBOX_VALUE",
]
# These expressions will be compiled with re.IGNORECASE
__case_insensitive__ = {"SANDBOX_VALUE"}

from content_security_policy.constants import (
    KEYWORD_SOURCES,
    WEBRTC_VALUES,
    SANDBOX_VALUES,
)

import re
from typing import cast

# https://tools.ietf.org/html/rfc5234#appendix-B.1
ALPHA = cast(re.Pattern, r"[A-Za-z]")
DIGIT = cast(re.Pattern, r"[0-9]")

# https://datatracker.ietf.org/doc/html/rfc9110#section-5.6.2
TOKEN_CHAR = f"[!#$%&'*+\-.^_`|~]|{ALPHA}|{DIGIT}"
TOKEN = cast(re.Pattern, f"({TOKEN_CHAR})+")

# https://w3c.github.io/webappsec-csp/#grammardef-base64-value
BASE64_VALUE = cast(re.Pattern, rf"({ALPHA}|{DIGIT}|[+\/\-_]){{2, 0}}={{0, 2}}")

# https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
UNRESERVED = f"({ALPHA}|{DIGIT}|[-._~])"
HEXDIG = "[0-9a-fA-F]"
PCT_ENCODED = f"%{HEXDIG}{HEXDIG}"
# Deviating from rfc3986 here, since CSP explicitly excludes ";" and ","
# https://w3c.github.io/webappsec-csp/#grammardef-path-part
SUB_DELIMS = "[!$&'()*+=]"
PCHAR = f"({UNRESERVED}|{PCT_ENCODED}|{SUB_DELIMS}|@|:)"
SEGMENT = f"{PCHAR}*"
SEGMENT_NZ = f"{PCHAR}+"  # Non-Zero
PATH_ABSOLUTE = f"/({SEGMENT_NZ}(/{SEGMENT})*)?"

# https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
SCHEME = cast(re.Pattern, rf"{ALPHA}({ALPHA}|{DIGIT}|[+-.])*")
HOST_CHAR = f"({ALPHA}|{DIGIT}|-)"
HOST_PART = rf"(\*|(\*\.)?{HOST_CHAR}+(\.{HOST_CHAR}+))"
PORT_PART = rf"(\*|{DIGIT}+)"
HOST_SOURCE = cast(
    re.Pattern, f"({SCHEME}://)?{HOST_PART}(:{PORT_PART})?{PATH_ABSOLUTE}?"
)

# https://w3c.github.io/webappsec-csp/#grammardef-keyword-source
KEYWORD_SOURCE = cast(re.Pattern, "|".join(KEYWORD_SOURCES))

# https://w3c.github.io/webappsec-csp/#directive-webrtc
WEBRTC_VALUE = cast(re.Pattern, "|".join(WEBRTC_VALUES))

# https://w3c.github.io/webappsec-csp/#directive-sandbox
SANDBOX_VALUE = cast(re.Pattern, "|".join(SANDBOX_VALUES))

# https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
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
IP_LITERAL = rf"\[{IP_V6_ADDRESS}\]"  # Fixme when I am dead: f"[({IP_V6_ADDRESS})|({IP_V_FUTURE})]"
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

URI = rf"{SCHEME}:{HIER_PART}(\?{QUERY})?(#{FRAGMENT})"

RELATIVE_PART = f"((//{AUTHORITY}{PATH_AB_EMPTY})|({PATH_ABSOLUTE})|({PATH_NOSCHEME}))?"
RELATIVE_REF = rf"({RELATIVE_PART})(\?{QUERY})?(#{FRAGMENT})?"

# https://datatracker.ietf.org/doc/html/rfc3986#section-4.1
URI_REFERENCE = cast(re.Pattern, f"({URI})|({RELATIVE_REF})")

# workaround for the "want to reuse patters but also want to precompile them"-problem
for name in __all__:
    if name in __case_insensitive__:
        locals()[name] = re.compile(locals()[name], flags=re.IGNORECASE)
    else:
        locals()[name] = re.compile(locals()[name])

# Convenience for debug
if __name__ == "__main__":
    for name in __all__:
        print(name)
        print(locals()[name].pattern)
