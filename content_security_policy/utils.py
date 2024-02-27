from abc import ABCMeta
import re
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


class KeywordMixin:
    _keywords: Iterable[str] = tuple()

    def __init_subclass__(cls, **kwargs):
        for name in cls._keywords:
            prop_name = name.strip("'").replace("-", "_")

            @classmethod  # type: ignore
            @property  # type: ignore
            def factory(cls, sneak_me=name):
                return cls(sneak_me)

            setattr(cls, prop_name, factory)

        pattern = re.compile("|".join(cls._keywords), flags=re.IGNORECASE)
        setattr(cls, "pattern", pattern)

        delattr(cls, "_keywords")
        super().__init_subclass__(**kwargs)
