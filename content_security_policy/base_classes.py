from __future__ import annotations
from abc import ABC
from typing import Type, TypeVar, Tuple, Generic, Union, Optional, Iterable

from content_security_policy.constants import (
    DEFAULT_VALUE_SEPARATOR,
    DEFAULT_POLICY_SEPARATOR,
)
from content_security_policy.exceptions import BadPolicy, BadSourceList
from content_security_policy.values import (
    SourceExpression,
    SourceList,
    NoneSrc,
    NoneSrcType,
)

SelfType = TypeVar("SelfType", bound="Directive")
ValueType = TypeVar("ValueType")


class Directive(ABC, Generic[ValueType]):
    _value: ValueType
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
        Return the complete value of the directive as a string
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
    A directive that only supports one value item.
    """

    # __init__ still allows for multiple values to be passed to enable lenient parsing.
    # TODO: When implementing is_valid, do not forget to check whether there is more than one value!
    def __init__(self, *values, **kwargs):
        super().__init__(*values, **kwargs)


# This is not called FetchDirective because not all directives accepting a Source List are categorised as
# Fetch Directives by the spec (worker-src, base-uri, form-action)
class SourceListDirective(Directive[SourceList], ABC):
    """
    A directive whose value is a
    """

    def __init__(self, *sources: Union[SourceExpression, NoneSrcType], **kwargs):
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadSourceList(
                f"{NoneSrc} may not be combined with other source expressions."
            )
        super().__init__(*sources, **kwargs)

    def __add__(self: SelfType, other: SourceExpression) -> SelfType:
        return type(self)(*self.values, other, name=self._name)


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
