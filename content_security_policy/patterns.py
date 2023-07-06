__all__ = ["ALPHA", "DIGIT", "BASE64_VALUE", "SCHEME", "HOST_SOURCE", "KEYWORD_SOURCE"]

from content_security_policy.constants import KEYWORD_SOURCES, WEBRTC_VALUES

import re
from typing import cast

# https://tools.ietf.org/html/rfc5234#appendix-B.1
ALPHA = cast(re.Pattern, r"[A-Za-z]")
DIGIT = cast(re.Pattern, r"[0-9]")

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

# workaround for the "want to reuse patters but also want to precompile them"-problem
for name in __all__:
    locals()[name] = re.compile(locals()[name])

# Convenience for debug
if __name__ == "__main__":
    for name in __all__:
        print(name)
        print(locals()[name].pattern)
