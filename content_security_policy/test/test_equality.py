from unittest import TestCase

from content_security_policy import *


class SingleValueItemTest(TestCase):
    cases = {
        NoneSrc: ("'none'", "'NoNe'"),
        TrustedTypesWildcard: ("*", "*"),
        SelfSrc: ("'self'", "'sElf'"),
    }

    def test_instances(self):
        for cls, vals in self.cases.items():
            with self.subTest(cls):
                val_a, val_b = vals
                a = cls(_value=val_a)
                b = cls(_value=val_b)
                self.assertEqual(a, b)
                self.assertEqual(b, a)

    def test_instance_class(self):
        for cls, vals in self.cases.items():
            with self.subTest(cls):
                _, val_b = vals
                b = cls(_value=val_b)
                self.assertEqual(cls, b)
                self.assertEqual(b, cls)
