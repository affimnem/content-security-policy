from unittest import TestCase

from content_security_policy.values import KeywordSource, NoneSrc
from content_security_policy.constants import KEYWORD_SOURCES, NONE
from content_security_policy.utils import kebab_to_snake


class KeywordSourceAttributes(TestCase):
    def test_keyword_source_attributes(self):
        for kw_src in KEYWORD_SOURCES:
            with self.subTest(kw_src):
                attr_name = kebab_to_snake(kw_src).strip("'")
                if not hasattr(KeywordSource, attr_name):
                    self.fail(f"{KeywordSource.__name__} has no attribute {attr_name}")
                elif not isinstance(getattr(KeywordSource, attr_name), KeywordSource):
                    self.fail(
                        f"{KeywordSource.__name__}.{attr_name} is not an instance of {KeywordSource}"
                    )


class NoneSourceStr(TestCase):
    def test_instance_str(self):
        self.assertEquals(str(NoneSrc()), NONE)

    def test_class_str(self):
        self.assertEquals(str(NoneSrc), NONE)
