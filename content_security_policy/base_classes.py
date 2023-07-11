from __future__ import annotations
from abc import ABC
import re
from typing import Type, TypeVar, Tuple, Generic, Optional, Iterable, Union

from content_security_policy.constants import (
    DEFAULT_VALUE_SEPARATOR,
    DEFAULT_POLICY_SEPARATOR,
)
from content_security_policy.exceptions import BadPolicy
from content_security_policy.utils import StrOnClassMeta


class ValueItem(ABC):
    """
    Base class for "items" in directive values. To clarify the distinction from a directive hash, consider:
    script-src 'self' http://example.com
    The hash of this script-src directive is "'self' http://example.com", whereas "'self'" and "http://example.com"
    are the "items" of the hash.
    The two are not mutually exclusive. Some items may also be valid values by themselves.
    """

    # Pattern used to identify these values when parsing
    _pattern: re.Pattern
    # hash as string
    _value: Optional[str]

    def __init__(self, value: str):
        self._value = value

    def __str__(self):
        return self._value


class ClassAsValue(ValueItem, metaclass=StrOnClassMeta):
    def __str__(self):
        """
        Calling str() on an instance will return the hash.
        """
        return self._value


# Some classes for directive values are valid items themselves, use this to cover both in type hints
ValueItemType = Union[ValueItem, Type[ValueItem]]

SelfType = TypeVar("SelfType", bound="Directive")
ValueType = TypeVar("ValueType", bound=ValueItemType)


class Directive(ABC, Generic[ValueType]):
    _value: Tuple[ValueType]
    _name: Optional[str]
    _separators: Optional[Tuple[str]]

    def __init__(
        self,
        *values: ValueType,
        _name: Optional[str] = None,
        _separators: Optional[Iterable[str]] = None,
    ):
        self._value = tuple(values)
        self._separators = _separators or (
            (DEFAULT_VALUE_SEPARATOR,) * len(self._value)
        )

        if _name:
            self._name = _name

    @property
    def name(self) -> str:
        """
        Name of the directive.
        """
        return self._name

    @property
    def values(self) -> Tuple[ValueType]:
        """
        All values of the directive as a tuple
        :return:
        """
        return self._value if isinstance(self._value, tuple) else (self._value,)

    def _value_str_tokens(self):
        value_it = iter(self.values)
        yield str(next(value_it))
        for sep in self._separators[1:]:
            yield sep
            yield str(next(value_it))

    @property
    def value(self) -> str:
        """
        Return the complete hash of the directive as a string
        :return:
        """
        return "".join(self._value_str_tokens())

    def _str_tokens(self):
        yield self.name
        yield self._separators[0]
        yield from self._value_str_tokens()

    def __str__(self):
        return "".join(self._str_tokens())

    def __iter__(self):
        """
        Iterate the directives values.
        """
        yield from self.values

    def __add__(self: SelfType, other: ValueType) -> SelfType:
        return type(self)(*self.values, other)

    def __sub__(self: SelfType, other: ValueType) -> SelfType:
        raise NotImplemented


class SingleValueDirective(Directive[ValueType], ABC, Generic[ValueType]):
    """
    A directive that only supports one hash item.
    """

    # __init__ still allows for multiple values to be passed to enable lenient parsing.
    # TODO: When implementing is_valid, do not forget to check whether there is more than one hash!
    def __init__(self, *values, **kwargs):
        super().__init__(*values, **kwargs)


class Policy:
    def __init__(self, *directives):
        if not directives:
            raise BadPolicy("Must provide at least one directive")
        self._directives = tuple(directives)

    @property
    def directives(self):
        return self._directives

    def __str__(self):
        return f"{DEFAULT_POLICY_SEPARATOR}".join(
            str(directive) for directive in self.directives
        )

    def __and__(self, other: Policy) -> PolicySet:
        raise NotImplemented

    def __add__(self, other: Directive) -> Policy:
        return type(self)(self.directives, other)

    def __sub__(self, other: Type[Directive]) -> Policy:
        raise NotImplemented

    def __getitem__(self, item: Type[Directive]):
        """
        Get a directive of the policy.
        :param item:
        :return:
        """
        raise NotImplemented

    def __getattr__(self, item):
        """
        Get a directive of the policy.
        :param item:
        :return:
        """
        raise NotImplemented

    def __iter__(self):
        """
        Iterate over directives.
        """
        yield from self._directives


class PolicySet:
    def __init__(self, *policies):
        raise NotImplemented
