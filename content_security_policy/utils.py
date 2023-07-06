import string
from typing import Iterable


def kebab_to_pascal(text: str) -> str:
    return string.capwords(text, "-").replace("-", "")


def kebab_to_snake(text: str) -> str:
    return "_".join(text.split("-"))


class StrOnClassMeta(type):
    _value: str

    def __str__(cls):
        """
        Calling str() on the CLASS will return the value.
        """
        return cls._value


class SingleValueClass(metaclass=StrOnClassMeta):
    _value: str
    _instance = None

    def __str__(self):
        """
        Calling str() on an instance will return the value.
        """
        return self._value

    def __new__(class_, *args, **kwargs):
        """
        Effectively makes this a singleton.
        """
        if not isinstance(class_._instance, class_):
            class_._instance = object.__new__(class_)
        return class_._instance


class AutoInstanceMixin:
    _auto_instance_prop: Iterable[str] = tuple()

    def __init_subclass__(cls, **kwargs):
        for name in cls._auto_instance_prop:
            prop_name = name.replace("-", "_").strip("'")

            @property
            @classmethod
            def factory(cls):
                return cls(name)

            setattr(cls, prop_name, factory)

        delattr(cls, "_auto_instance_prop")
        super().__init_subclass__(**kwargs)
