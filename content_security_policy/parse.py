__all__ = [
    "directive_from_string",
]

from typing import *
from content_security_policy import *
from content_security_policy.directives import directive_by_name, UnrecognizedDirective
from content_security_policy.exceptions import ParsingError, NoSuchDirective
from content_security_policy.patterns import ASCII_WHITESPACE

_PARSING_RULES: Dict[Type[Directive], Tuple[Type[ValueItem]]] = {
    UnrecognizedDirective: tuple(),
    SourceListDirective: (
        NoneSrc,
        KeywordSource,
        HashSrc,
        NonceSrc,
        HostSrc,
        SchemeSrc,
    ),
    Webrtc: (WebrtcValue,),
    Sandbox: (SandboxToken,),
    FrameAncestors: (NoneSrc, SelfSrc, HostSrc, SchemeSrc),
    ReportUriValue: (UriReference,),
    ReportTo: (ReportToValue,),
}


def value_item_from_string(
    value_string: str, directive_type: Type[Directive]
) -> ValueItemType:
    """
    Create a directive hash object from a string.
    :param value_string: Directive hash (without whitespace!)
    :param directive_type: Directive which has hash, needed to distinguish certain hash types.
    :return: Object representing the hash.
    """
    for d_type, value_types in _PARSING_RULES.items():
        if issubclass(directive_type, d_type):
            for v_type in value_types:
                if v_type.pattern.fullmatch(value_string):
                    v_type = cast(Type[ValueItem], v_type)
                    return v_type(value_string)

            return UnrecognizedValueItem(value_string)

    raise ValueError(
        f"Failed to find parsing rules for directive type {directive_type}"
    )


def directive_from_string(directive_string: str) -> Directive:
    separators = ASCII_WHITESPACE.findall(directive_string)
    tokens = ASCII_WHITESPACE.split(directive_string)
    if len(separators) != (len(tokens) - 1):
        raise ParsingError(
            "Mismatch in amount of tokens and separators. "
            "Perhaps your directive is not trimmed?"
        )
    if len(tokens) == 0:
        raise ParsingError("No directive name found in directive string.")

    name, value_items = tokens[0], tokens[1:]
    try:
        dir_class = directive_by_name(name.lower())
    except NoSuchDirective:
        dir_class = UnrecognizedDirective
    dir_class = cast(Type[Directive], dir_class)

    values = (
        value_item_from_string(item, directive_type=dir_class) for item in value_items
    )
    return dir_class(*values, _name=name, _separators=tuple(separators))


def policy_from_string(directive_string: str) -> Policy:
    raise NotImplemented


def policy_set_from_string(header_string: str) -> PolicySet:
    raise NotImplemented
