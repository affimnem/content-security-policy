from unittest import TestCase

from content_security_policy import *


class SimpleExample(TestCase):
    def test_1(self):
        policy = Policy(
            DefaultSrc(KeywordSource.self), FrameAncestors(SelfSrc), ObjectSrc(NoneSrc)
        )
        self.assertEquals(
            str(policy), "default-src 'self'; frame-ancestors 'self'; object-src 'none'"
        )
