from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Type, TypeVar

from content_security_policy.constants import CSPLevels
from content_security_policy.exceptions import BadDirective, BadPolicy
from content_security_policy.sources import SourceExpression


class Directive(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Name of the directive.
        """


SameClass = TypeVar("SameClass", bound=Directive)


class SrcDirective(Directive, ABC):
    def __init__(self, *sources: SourceExpression):
        if not sources:
            raise BadDirective(f"Must provide at least one source expression.")
        self._sources = tuple(sources)

    @property
    def sources(self):
        return self._sources

    def __add__(self: SameClass, other: SourceExpression) -> SameClass:
        return type(self)(*self._sources, other)

    def __sub__(self: SameClass, other: SourceExpression) -> SameClass:
        raise NotImplemented


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
        """Iterate over directives.
        :return:
        """
        yield from self._directives

    def get_effective_policy(self, level: CSPLevels = CSPLevels.level_3) -> Policy:
        """
        Return a policy with all directives and directive arguments that a browser with level `level` would ignore.
        :param level:
        :return:
        """
        raise NotImplemented


class PolicySet:
    def __init__(self, *policies):
        raise NotImplemented

    def get_effective_policy_set(
            self, level: CSPLevels = CSPLevels.level_3
    ) -> "Policy":
        raise NotImplemented
