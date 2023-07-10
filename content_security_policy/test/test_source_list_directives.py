from unittest import TestCase

from content_security_policy import directive_by_name, FrameAncestors
from content_security_policy import NoneSrc, KeywordSource, SelfSrc
from content_security_policy.constants import SOURCE_LIST_DIRECTIVES
from content_security_policy.exceptions import BadSourceList, BadDirectiveValue


class DoNotCombineNoneSource(TestCase):
    def test_source_list_directives_constructor(self):
        for directive in SOURCE_LIST_DIRECTIVES:
            with self.subTest(directive):
                directive_cls = directive_by_name(directive)
                with self.assertRaises(BadSourceList):
                    directive_cls(NoneSrc, KeywordSource.self)

    def test_source_list_directives_addition(self):
        for directive in SOURCE_LIST_DIRECTIVES:
            with self.subTest(directive):
                directive_cls = directive_by_name(directive)
                instance = directive_cls(NoneSrc)
                with self.assertRaises(BadSourceList):
                    instance += KeywordSource.self

    def test_frame_ancestors_constructor(self):
        with self.assertRaises(BadDirectiveValue):
            FrameAncestors(NoneSrc, SelfSrc)
