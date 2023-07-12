from __future__ import annotations
from abc import ABC
import re
from functools import cached_property, cache
from typing import Type, TypeVar, Tuple, Generic, Optional, Iterable, Union

from content_security_policy.constants import (
    DEFAULT_VALUE_SEPARATOR,
    DEFAULT_DIRECTIVE_SEPARATOR,
    DEFAULT_POLICY_SEPARATOR,
)
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
    pattern: re.Pattern
    # hash as string
    _value: Optional[str]

    def __init__(self, value: str, _value: Optional[str] = None):
        # The arguments are this awkward because all concrete implementations of ValueItem use their first argument
        # for the "human friendly" construction of values. The kw arg "_value" is then used to create values from
        # strings. Both are included here so the type-checker recognizes that all ValueItem constructors accept the
        # _value kw_arg.
        self._value = value or _value

    def __str__(self):
        return self._value

    @classmethod
    def from_string(cls: Type[SelfType], str_value: str) -> SelfType:
        """
        Return an instance of the class from a string value using the `_value` kwarg.
        Note that __init__ on subclasses of ValueItem MUST Ignore any other arguments if _value is passed.
        ValueItem subclasses MUST override this method if their __init__ has a different argument structure.
        :param str_value: value to pass to _value.
        :return: Instance of the class.
        """
        return cls("", _value=str_value)


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
    _separators: Tuple[str]

    def __init__(
        self,
        *values: ValueType,
        _name: Optional[str] = None,
        _separators: Optional[Iterable[str]] = None,
    ):
        self._value = tuple(values)

        self._separators = (
            tuple(_separators)
            if _separators is not None
            else ((DEFAULT_VALUE_SEPARATOR,) * len(self._value))
        )

        if _name is not None:
            self._name = _name

    @property
    def name(self) -> str:
        """
        Name of the directive.
        """
        return self._name

    @cached_property
    def values(self) -> Tuple[ValueType]:
        """
        All values of the directive as a tuple
        :return:
        """
        return self._value if isinstance(self._value, tuple) else (self._value,)

    @property
    def _value_str_tokens(self):
        value_it = iter(self.values)
        try:
            yield str(next(value_it))
        except StopIteration:
            # Happens if self.values is empty (no-value directives)
            return
        for sep, value in zip(self._separators[1:], value_it):
            yield sep
            yield str(value)

    @property
    def _str_tokens(self):
        yield self.name
        if self._separators:
            yield self._separators[0]
        yield from self._value_str_tokens

    @cached_property
    def value(self) -> str:
        """
        Return the complete value of the directive as a string
        :return:
        """
        return "".join(self._value_str_tokens)

    @cache
    def __str__(self):
        return "".join(self._str_tokens)

    def __iter__(self):
        """
        Iterate the directives values.
        """
        yield from self.values

    def __add__(self: SelfType, other: ValueType) -> SelfType:
        separators = self._separators + (DEFAULT_VALUE_SEPARATOR,)
        return type(self)(*self.values, other, _separators=separators)

    def __sub__(self: SelfType, other: ValueType) -> SelfType:
        raise NotImplemented


class SingleValueDirective(Directive[ValueType], ABC, Generic[ValueType]):
    """
    A directive that only supports one hash item.
    """

    # __init__ still allows for multiple values to be passed to enable lenient parsing.
    # TODO: When implementing is_valid, do not forget to check whether there is more than one value!
    def __init__(self, *values, **kwargs):
        super().__init__(*values, **kwargs)


class Policy:
    _separators: Optional[Tuple[str]]

    def __init__(
        self,
        *directives,
        _separators: Optional[Iterable[str]] = None,
    ):
        self._directives = tuple(directives)
        self._separators = (
            tuple(_separators)
            if _separators is not None
            else ((DEFAULT_DIRECTIVE_SEPARATOR,) * (len(self._directives) - 1))
        )

    @property
    def directives(self):
        return self._directives

    @property
    def _str_tokens(self):
        directives_it = iter(self.directives)
        yield str(next(directives_it))
        for sep, directive in zip(self._separators, directives_it):
            yield sep
            yield str(directive)

    @cache
    def __str__(self):
        return "".join(self._str_tokens)

    def __and__(self, other: Policy) -> PolicyList:
        return PolicyList(self, other)

    def __add__(self, other: Directive) -> Policy:
        separators = self._separators + (DEFAULT_DIRECTIVE_SEPARATOR,)
        return type(self)(*self.values, other, _separators=separators)

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


class PolicyList:
    _policies: Tuple[Policy]
    _separators: Tuple[str]

    def __init__(
        self,
        *policies: Policy,
        _separators: Optional[Iterable[str]] = None,
        _head: Optional[str] = None,
        _tail: Optional[str] = None,
    ):
        self._policies = tuple(policies)
        self._separators = (
            tuple(_separators)
            if _separators is not None
            else ((DEFAULT_POLICY_SEPARATOR,) * (len(self._policies) - 1))
        )
        self._head = _head
        self._tail = _tail

    @property
    def _str_tokens(self):
        if self._head:
            yield self._head

        policy_it = iter(self._policies)
        yield str(next(policy_it))

        for sep, policy in zip(self._separators, policy_it):
            yield sep
            yield str(policy)

        if self._tail:
            yield self._tail

    @cache
    def __str__(self):
        return "".join(self._str_tokens)
