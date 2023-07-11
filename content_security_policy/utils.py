from abc import ABCMeta

import string
from typing import Iterable


def kebab_to_pascal(text: str) -> str:
    return string.capwords(text, "-").replace("-", "")


def kebab_to_snake(text: str) -> str:
    return "_".join(text.split("-"))


class StrOnClassMeta(ABCMeta):
    _value: str

    def __str__(cls):
        """
        Calling str() on the CLASS will return  _value.
        """
        return cls._value


class AutoInstanceMixin:
    _auto_instance_prop: Iterable[str] = tuple()

    def __init_subclass__(cls, **kwargs):
        for name in cls._auto_instance_prop:
            prop_name = name.strip("'").replace("-", "_")

            @classmethod
            @property
            def factory(cls, sneak_me=name):
                return cls(sneak_me)

            setattr(cls, prop_name, factory)

        delattr(cls, "_auto_instance_prop")
        super().__init_subclass__(**kwargs)
