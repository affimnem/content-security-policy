__all__ = ["value_item_from_string", "directive_from_string", "policy_from_string"]

from typing import *
from content_security_policy import *
from content_security_policy.exceptions import ParsingError, NoSuchDirective
from content_security_policy.patterns import (
    VALUE_ITEM_SEPARATOR,
    DIRECTIVE_SEPARATOR,
    POLICY_SEPARATOR,
    WHITESPACE_HEAD,
)

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
    ReportUri: (UriReference,),
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
        try:
            if issubclass(directive_type, d_type):
                for v_type in value_types:
                    if v_type.pattern.fullmatch(value_string):
                        v_type = cast(Type[ValueItem], v_type)
                        return v_type.from_string(value_string)

                return UnrecognizedValueItem(value_string)
        except Exception as e:
            print(e)

    raise ValueError(
        f"Failed to find parsing rules for directive type {directive_type}"
    )


def directive_from_string(directive_string: str) -> Directive:
    separators = VALUE_ITEM_SEPARATOR.findall(directive_string)
    tokens = VALUE_ITEM_SEPARATOR.split(directive_string)
    if len(separators) != (len(tokens) - 1):
        raise ParsingError(
            "Mismatch in amount of tokens and separators. "
            "Perhaps your directive is not trimmed?"
        )
    if len(tokens) == 0:
        raise ParsingError("No directive name found in directive string.")

    name, value_items = tokens[0], tokens[1:]
    try:
        dir_class = Directive.class_by_name(name.lower())
    except NoSuchDirective:
        dir_class = UnrecognizedDirective
    dir_class = cast(Type[Directive], dir_class)

    values = (
        value_item_from_string(item, directive_type=dir_class) for item in value_items
    )
    return dir_class(*values, _name=name, _separators=tuple(separators))


def policy_from_string(policy_string: str) -> Policy:
    separators = DIRECTIVE_SEPARATOR.findall(policy_string)
    tokens = DIRECTIVE_SEPARATOR.split(policy_string)
    if len(separators) != (len(tokens) - 1):
        raise ParsingError(
            "Mismatch in amount of tokens and separators. "
            "Perhaps your policy is not trimmed?"
        )

    return Policy(
        *(directive_from_string(dir) for dir in tokens), _separators=separators
    )


def policy_list_from_string(policy_list_string: str) -> PolicyList:
    head = WHITESPACE_HEAD.match(policy_list_string).group(0)
    policy_list_string = WHITESPACE_HEAD.sub("", policy_list_string)

    # I have given up on a regex replace for trailing whitespace...
    policy_list_string = policy_list_string[::-1]
    tail = WHITESPACE_HEAD.match(policy_list_string).group(0)[::-1]
    policy_list_string = WHITESPACE_HEAD.sub("", policy_list_string)
    policy_list_string = policy_list_string[::-1]

    separators = POLICY_SEPARATOR.findall(policy_list_string)
    tokens = POLICY_SEPARATOR.split(policy_list_string)
    return PolicyList(
        *(policy_from_string(pol) for pol in tokens),
        _head=head,
        _tail=tail,
        _separators=separators,
    )
