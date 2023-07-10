from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Type, TypeVar, Tuple, Generic

from content_security_policy.constants import CSPLevels, VALUE_SEPARATOR
from content_security_policy.exceptions import BadPolicy, BadSourceList
from content_security_policy.values import SourceExpression, SourceList, NoneSrc

SelfType = TypeVar("SelfType", bound="Directive")
ValueType = TypeVar("ValueType")


class Directive(ABC, Generic[ValueType]):
    _value: ValueType

    def __init__(self, *values: ValueType):
        self._value = tuple(values)

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Name of the directive.
        """

    @property
    def value(self) -> str:
        """
        Return the complete value of the directive as a string
        :return:
        """
        return VALUE_SEPARATOR.join(self.values)

    @property
    def values(self) -> Tuple[ValueType]:
        """
        All values of the directive as a tuple
        :return:
        """
        return self._value if isinstance(self._value, tuple) else (self._value,)

    def __str__(self):
        return f"{self.name}{VALUE_SEPARATOR}{self.value}"

    def __iter__(self):
        """
        Iterate the directives values.
        """
        yield from self.values

    def __add__(self: SelfType, other: ValueType) -> SelfType:
        return type(self)(*self.values, other)

    def __sub__(self: SelfType, other: ValueType) -> SelfType:
        raise NotImplemented

    def get_effective_directive(self: SelfType) -> SelfType:
        """
        Return a directive without any values that a browser with level `level` would ignore.
        """


class SingleValueDirective(Directive, ABC):
    def __init__(self, value):
        super().__init__(value)


class FetchDirective(Directive[SourceList], ABC):
    def __init__(self, *sources: SourceExpression):
        if len(sources) > 1 and any(src == NoneSrc for src in sources):
            raise BadSourceList(
                f"{NoneSrc} may not be combined with other source expressions."
            )
        super().__init__(*sources)

    def __add__(self: SelfType, other: SourceExpression) -> SelfType:
        if self.values and other == NoneSrc:
            raise BadSourceList(
                f"{NoneSrc} may not be combined with other source expressions."
            )

        return type(self)(*self.values, other)


class Policy:
    def __init__(self, *directives):
        if not directives:
            raise BadPolicy("Must provide at least one directive")
        self._directives = tuple(directives)

    @property
    def directives(self):
        return self._directives

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

    def get_effective_policy(self, level: CSPLevels = CSPLevels.level_3) -> Policy:
        """
        Return a policy without any directives or directive values that a browser with level `level` would ignore.
        """
        raise NotImplemented


class PolicySet:
    def __init__(self, *policies):
        raise NotImplemented

    def get_effective_policy_set(
        self, level: CSPLevels = CSPLevels.level_3
    ) -> PolicySet:
        """
        Return a policy set without any directives or directive values that a browser with level `level` would ignore.
        """
        raise NotImplemented
